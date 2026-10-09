# Demo script: 3 minutes, 3 slides then live

CloudTrail delivers events a few minutes late, so the live change is started **before recording** and the video shows its result.

## Pre-flight (start 10 minutes before recording)
1. `aws sso login --profile $WARDEN_PROFILE`
2. `prowler-warden preflight` and fix anything marked FAIL.
3. In the dashboard: **Remediation**, set mode **Self-fix**, untick dry-run, tick **Open real pull requests**, tick **Watch CloudTrail**.
4. `prowler-warden live reset`, then `prowler-warden live start`. This opens port 22 on the throwaway group. Start it at least 6 minutes before recording.
5. **Cost & signals**: click **Inject demo cost spike**.
6. Open in tabs: the dashboard (`#overview`), the deck, the Slack channel `alert-demo-prowler`, the demo repo's pull requests, the status page.
7. Confirm the five-step tracker under **Remediation** shows runtime fix and code PR done before you press record.

## Recording with the autopilot (recommended)
Narration timing and screen switching are driven by `src/warden/static/script.json`, so you only narrate.
1. Run `prowler-warden serve --port 8799`. Open **http://localhost:8799/teleprompter** on a second screen or window that is **not** recorded.
2. Open the dashboard in the recorded window and the deck in another tab. Open the Slack channel and the status page in two more tabs.
3. Start Screen Studio. Press **Space** on the teleprompter to start the 3:00 clock, and read the slides from the deck (the teleprompter tells you when to change slide).
4. At **0:48**, switch to the dashboard tab and click **Start demo** (top right). The dashboard then changes view, scrolls and highlights the right panel on its own, with a small cue box (add `?hud=0` to the URL to hide it).
5. At **2:15** and **2:25** the teleprompter says "Switch tab": go to Slack, then to the status page. At **2:45** return to the dashboard.
6. **Esc** stops the autopilot. **R** resets the teleprompter.

## Timing rules
- **Hard cap 3:00 for everything**: 3 slides (0:48) plus the live demo (2:12). Aim to finish at 2:50.
- Narration is about 270 words, roughly 110 seconds at a normal pace, so the rest of each slot is screen time. Do not add words.
- Record with a visible timer. If you are more than 5 seconds behind at 1:10, drop the **Cost & signals** segment (15 s).
- Cut order if still long: Cost & signals (15 s), then the Status page line (10 s), then the Slack screen (keep one sentence).
- Never cut: the cover line, the detection to fix to PR chain, and the closing sponsor line.

## Timeline
| Time | On screen | Say |
|---|---|---|
| 0:00 | Slide 1, Cover | "Prowler Warden is the agent that keeps your cloud secure and compliant, autonomously." |
| 0:08 | Slide 2, Problem and solution | "Compliance is a snapshot. Scans go stale, console fixes never reach Terraform so the next apply undoes them, and every finding looks equally urgent. Warden detects, decides what is actually being used, fixes in AWS and in code, and proves it. One runtime switch picks self-fix or human PR review." |
| 0:30 | Slide 3, Architecture | "Prowler scans, CloudTrail and Cost Explorer feed ClickHouse. Rules and a Claude agent decide. Actions are real: an AWS fix, a Semgrep-gated PR, a Slack alert from an agent hosted on Guild.ai, and a public status page." |
| 0:48 | Dashboard, **Overview** | "Real account, CIS 5.0: 28.8%. The simulator shows the path: self-fix gets 34.6, pull requests to code 84.6, and only people can finish the last 15 percent, like root MFA." |
| 1:10 | **Cost & signals** | "Compliance says what is misconfigured. Cost says what is being used. EC2 spend is 13x its baseline, so open-to-internet findings in EC2 now rank as likely being used." |
| 1:25 | **Live events** | "This is CloudTrail, live. Six minutes ago someone opened SSH to the internet on a test group." Point at the detection row: "Prowler re-checked and confirmed the violation." |
| 1:47 | **Remediation**, five-step tracker | "Self-fix mode closed the port in AWS and Prowler verified it. It also opened a pull request that removes the same rule from Terraform, so the next apply cannot reopen it." Click the PR link. |
| 2:15 | Slack channel | "The Guild.ai agent posted the alert to Slack." |
| 2:25 | Status page | "And Warden published a redacted status page with a SHA-256 over the evidence, so anyone can verify it was not edited." |
| 2:45 | Dashboard | "Three sponsor tools in the loop: ClickHouse, Guild.ai and Semgrep. Click Revert to undo, or Reset demo to run it again." |
| 3:00 | End | |

## If something fails on the day
- **No detection yet**: CloudTrail is slow. Show the earlier completed chain in the **Live events** history, or record the live part again once it lands.
- **Slack silent**: show the Guild session (`guild session list`) as proof the agent ran, then say the Slack post lags.
- **PR step skipped**: leave "Open real pull requests" off and show the prepared branch in the action log instead.
- **Reset between takes**: `prowler-warden live reset`, then `prowler-warden live start`, wait 6 minutes.
