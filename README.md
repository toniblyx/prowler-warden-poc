# Prowler Warden

An always-on agent that keeps an AWS account compliant with a framework you pick (CIS, SOC2, PCI, HIPAA, NIST and 40+ others),
and fixes drift both in AWS and in the Terraform that owns it.

Built for the Cyberdefense Hackathon (San Francisco, Oct 9 2026) on **Prowler OSS**, not the Cloud product.

## The problem
Compliance is treated as a snapshot. Scans go stale, fixes made in the console never reach Terraform (the next `apply` reopens
the hole), and every finding looks equally urgent even though only some are being used.

## What Warden does
| Step | How |
|---|---|
| **Detect** | **Prowler real-time**: risky API calls reach Prowler through EventBridge in seconds. A rule maps each call to the compliance checks it can break, and a **targeted Prowler check** on that exact resource confirms the violation. Prowler decides; ClickHouse only stores the evidence. |
| **Decide** | Cost Explorer spikes and suspicious CloudTrail activity mark a finding as "likely being used", not just present. |
| **Fix** | A runtime switch picks the response: **monitor**, **PR review** (human reviews a pull request) or **self-fix** (Warden changes AWS, then opens a PR so the code matches). |
| **Prove** | Prowler re-verifies, a Guild.ai agent posts a Slack alert, and a redacted, SHA-256-stamped status page is published. |

## Architecture
```
AWS account                         Prowler Warden                                      Real actions
-----------                         --------------                                      ------------
Prowler OSS scans  ─────────────►  ┌─ Prowler real-time ─────────────────┐   ──►  AWS self-fix (boto3, re-verified by Prowler)
API calls ► EventBridge ► SQS ───► │ event ► rule ► targeted Prowler check│   ──►  GitHub PR (Semgrep gate) on warden-map'd Terraform
Cost Explorer ──────────────────►  └──────────────┬──────────────────────┘   ──►  Slack alert (agent hosted on Guild.ai)
                                                   ▼                           ──►  Status page (hash-stamped evidence)
                                     ClickHouse (findings, events, cost, detections, policy)
                                     + exploitability signals + Claude agent + runtime policy
```
`inventory.py` mirrors the live account as Terraform (with import blocks) and writes `warden-map.json`, a map from AWS ids to
Terraform addresses. That map is how a runtime fix finds the code it must also change.

## Sponsor tools used
- **ClickHouse**: every finding, CloudTrail event, cost row, detection and policy. Posture over 3.4M rows computes in about 300 ms.
- **Guild.ai**: hosts the published `warden-alerts` agent. Warden calls its API trigger on each action and the agent posts to Slack through Guild's Slack integration.
- **Semgrep**: gates every AI-written Terraform patch (`p/terraform` rules via the open-source CLI) before a PR opens.

Not used: Senso.ai and Akash/AkashML.

## Run it
```bash
docker run -d --name warden-ch -p 8123:8123 -e CLICKHOUSE_USER=default -e CLICKHOUSE_PASSWORD=warden clickhouse/clickhouse-server
uv venv --python 3.12 ~/venvs/prowler-warden && VIRTUAL_ENV=~/venvs/prowler-warden uv pip install -e . semgrep -e /path/to/prowler
cp .env.example .env            # ANTHROPIC_API_KEY, WARDEN_PROFILE, WARDEN_ACCOUNT, GUILD_* ...
prowler-warden scan --profile <aws-profile> --framework cis_5.0_aws
prowler-warden realtime deploy # EventBridge rule + SQS queue: API calls reach Prowler in seconds
prowler-warden costs <account> --profile <aws-profile>
prowler-warden serve --port 8799        # dashboard; turn on the CloudTrail watcher there
prowler-warden preflight                # checks everything the live demo needs
prowler-warden publish                  # redacted status page in site/
```
Useful commands: `prowler-warden mode set monitor|pr|auto`, `prowler-warden live start|reset|status`, `prowler-warden review <account>`, `prowler-warden fix <account> <repo>`.

## Safety model
- Default mode is **PR review** with **dry-run on**. Self-fix must be switched on, and the UI shows a red LIVE banner.
- Auto-fix acts only on the resource named in the triggering CloudTrail event, never on unrelated failures.
- Fixes are narrow, idempotent boto3 calls with a recorded undo (Revert button). Checks without a safe fix fall back to a PR.
- The live demo touches only a throwaway VPC and security group tagged `warden-demo`.
- The public status page omits account ids, resource ARNs and actor identities.

## Honest limitations
- Scans cover one region (`us-east-1`). Selecting another framework reuses existing results and offers a scan for missing checks.
- The real-time feed needs a small CloudFormation stack (`prowler-warden realtime deploy`: one EventBridge rule and one SQS queue). Without it Warden falls back to CloudTrail `LookupEvents`, which lags by about 3 to 6 minutes.
- Code patching is deterministic only for open security group rules. Other checks hand off to the Fixer agent (`prowler-warden fix`).
- Cost is a lagging signal (about 24 hours) and is evidence to investigate, not proof of compromise. The demo cost spike is a clearly labelled synthetic overlay.
- 100% compliance is not literally guaranteed: root MFA needs a person, and some requirements cost money or risk lockouts. The fix simulator shows exactly how far each class of fix goes.

## License
Apache-2.0. See `LICENSE` and `NOTICE`. The Prowler name and logos belong to Prowler.
