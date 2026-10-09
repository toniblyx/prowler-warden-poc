// Warden alert formatter: receives an action payload from Prowler Warden
// (API trigger) and posts one concise alert to Slack.
import { guildServiceTool, llmAgent } from "@guildai/agents-sdk";
import { z } from "zod";

const slack_chat_post_message = guildServiceTool("slack", {
  description: "Post a message to a Slack channel (mrkdwn supported).",
  inputSchema: z.object({
    channel: z.string().describe("Channel ID or #name"),
    text: z.string().describe("Message text in Slack mrkdwn"),
  }),
  outputSchema: z.object({
    ok: z.boolean(),
    ts: z.string().optional(),
    error: z.string().optional(),
  }),
});

const systemPrompt = `
You are the Prowler Warden alert bot. You receive ONE structured event describing
an action Warden took on an AWS account. Post exactly ONE Slack message with
slack_chat_post_message to the given channel, then reply "posted" (or the Slack
error if ok is false). Never post more than once. Do not ask questions.

Message format (Slack mrkdwn, max 6 lines, no preamble):
Line 1: <emoji> *<headline>*  where emoji/headline come from action_kind and status:
  - self-fix + fixed-verified            -> :white_check_mark: "Warden self-fixed <check_id> (verified)"
  - self-fix + fix-applied-still-failing -> :warning: "Fix applied but <check_id> still failing"
  - self-fix + failed                    -> :x: "Self-fix FAILED for <check_id>"
  - self-fix + dry-run                   -> :test_tube: "Dry run: Warden would fix <check_id>"
  - pr + pr-opened / pr-ready            -> :git-pull-request: "Warden opened a PR for <check_id>" (pr-ready: "prepared a branch")
  - detection (any status)               -> :rotating_light: "Violation detected: <check_id>"
  - anything else                        -> :information_source: short neutral headline
Line 2: \`resource\` in account \`account\` | severity: *severity* | framework: framework | mode: mode
Line 3: What happened and why it matters, one sentence derived from summary (and requirements, if given, name up to 3).
Line 4: What Warden did / status: status.
Line 5 (only if pr_url given): <pr_url|View PR>

Use only facts from the input. Do not invent details. Severity critical/high may be
prefixed with :red_circle:. Keep it under 600 characters.
`;

export default llmAgent({
  description: "Formats Prowler Warden actions into concise Slack alerts.",
  inputSchema: z.object({
    action_kind: z.enum(["self-fix", "pr", "detection"]),
    severity: z.string().default("unknown"),
    check_id: z.string(),
    resource: z.string(),
    account: z.string(),
    summary: z.string(),
    status: z.string(),
    pr_url: z.string().optional(),
    mode: z.string().default("unknown"),
    framework: z.string().default("unknown"),
    requirements: z.array(z.string()).optional(),
    channel: z.string().default("#warden-alerts").describe("Slack channel ID or #name"),
  }),
  inputTemplate: `Post this Warden event to Slack channel {{channel}}:
action_kind: {{action_kind}}
severity: {{severity}}
check_id: {{check_id}}
resource: {{resource}}
account: {{account}}
summary: {{summary}}
status: {{status}}
pr_url: {{pr_url}}
mode: {{mode}}
framework: {{framework}}
requirements: {{requirements}}`,
  tools: { slack_chat_post_message },
  systemPrompt,
});
