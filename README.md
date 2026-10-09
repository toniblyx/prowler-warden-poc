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
| **Detect** | Prowler OSS scans plus CloudTrail events in near real time. A rule maps each risky API call to the compliance checks it can break, then a targeted Prowler re-check confirms the violation. |
| **Decide** | Cost Explorer spikes and suspicious CloudTrail activity mark a finding as "likely being used", not just present. |
| **Fix** | A runtime switch picks the response: **monitor**, **PR review** (human reviews a pull request) or **self-fix** (Warden changes AWS, then opens a PR so the code matches). |
| **Prove** | Prowler re-verifies, a Guild.ai agent posts a Slack alert, and a redacted, SHA-256-stamped status page is published. |

## Architecture
```
AWS account                 Warden                                          Real actions
-----------                 ------                                          ------------
Prowler OSS scans   ──►  ClickHouse  ◄── rules, drift, cost signals  ──►  AWS self-fix (boto3, re-verified by Prowler)
CloudTrail events   ──►  (findings,       Claude agent (tool use)     ──►  GitHub PR (Semgrep gate) against warden-map'd Terraform
Cost Explorer       ──►   events, cost,   runtime policy              ──►  Slack alert (agent hosted on Guild.ai)
                          detections)                                 ──►  Status page (hash-stamped evidence)
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
warden scan --profile <aws-profile> --framework cis_5.0_aws
warden costs <account> --profile <aws-profile>
warden serve --port 8799        # dashboard; turn on the CloudTrail watcher there
warden preflight                # checks everything the live demo needs
warden publish                  # redacted status page in site/
```
Useful commands: `warden mode set monitor|pr|auto`, `warden live start|reset|status`, `warden review <account>`, `warden fix <account> <repo>`.

## Safety model
- Default mode is **PR review** with **dry-run on**. Self-fix must be switched on, and the UI shows a red LIVE banner.
- Auto-fix acts only on the resource named in the triggering CloudTrail event, never on unrelated failures.
- Fixes are narrow, idempotent boto3 calls with a recorded undo (Revert button). Checks without a safe fix fall back to a PR.
- The live demo touches only a throwaway VPC and security group tagged `warden-demo`.
- The public status page omits account ids, resource ARNs and actor identities.

## Honest limitations
- Scans cover one region (`us-east-1`). Selecting another framework reuses existing results and offers a scan for missing checks.
- CloudTrail `LookupEvents` delivers events with a delay of a few minutes. True real time needs EventBridge, which is the next step.
- Code patching is deterministic only for open security group rules. Other checks hand off to the Fixer agent (`warden fix`).
- Cost is a lagging signal (about 24 hours) and is evidence to investigate, not proof of compromise. The demo cost spike is a clearly labelled synthetic overlay.
- 100% compliance is not literally guaranteed: root MFA needs a person, and some requirements cost money or risk lockouts. The fix simulator shows exactly how far each class of fix goes.
