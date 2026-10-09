# Submission checklist

| Deliverable | Where |
|---|---|
| GitHub repository | https://github.com/toniblyx/prowler-warden-poc (public, Apache-2.0). The demo infra it opens PRs against is `toniblyx/prowler-warden-demo-infra` (private). |
| Demo video (3 minutes max) | **TODO**: record with `docs/DEMO_SCRIPT.md`, upload, paste the share link here. |
| Documentation of what was built and tools used | `README.md`, this file, `docs/DEMO_SCRIPT.md` |
| Team names and contact emails | Toni de la Fuente, toni@prowler.com (solo) |
| Optional: screenshot and working site | Status page artifact: https://claude.ai/artifact/4cfjMwart2nHzW8RUj2yPR (private until shared). Pitch deck: https://claude.ai/artifact/LrNFBC7AvzMKme6EycHF36 |

**Team:** Toni de la Fuente (toni@prowler.com), solo entry

## Challenge fit
- **Preserve what matters**: continuous compliance posture, and the evidence for it (verified fixes, hash-stamped status page).
- **Real work, real action**: runtime AWS fix, GitHub pull request against Terraform, Slack alert, published status page.
- **Grounded in truthful sources**: Prowler OSS check results, AWS CloudTrail and Cost Explorer, with each framework requirement taken from Prowler's own framework definitions.
- **Monitor, orchestrate**: a CloudTrail watcher, a policy router (monitor, PR, self-fix), and a Guild.ai-hosted alert agent triggered over its API.

## Sponsor tools (three in real use)
1. **ClickHouse**: storage and analytics for findings, events, cost, detections and policy.
2. **Guild.ai**: published agent `toni~warden-alerts`, API trigger, Slack integration.
3. **Semgrep**: gate on every AI-written Terraform patch.

Not used: Senso.ai, Akash/AkashML.

## Before you submit
- Rotate or remove anything secret: `.env` is git-ignored. The Guild trigger key and the Anthropic key live only there.
- Set the remediation mode back to PR review and run `prowler-warden live reset` so no demo resources remain in the AWS account.
