# Warden -> Guild.ai -> Slack alerts

Flow: `warden.notify.send_action` (HTTPS POST, stdlib) -> Guild API trigger -> agent `toni~warden-alerts` (TypeScript LLM agent in `warden-alerts/`) -> `slack_chat_post_message` via the Guild Slack integration.

Already done (CLI): agent `toni~warden-alerts` created and a DRAFT version saved/validated (build OK, not published); workspace `toni~prowler-warden` created.

## Manual steps (Guild web UI, https://app.guild.ai)

1. **Connect Slack**: Credentials -> Slack -> Connect, authorize the Slack workspace (scopes include `chat:write`).
2. **Invite the bot** to the alert channel in Slack (`/invite @Guild`), or use a public channel the app can post to.
3. **Install the agent in the workspace**: open workspace `prowler-warden` -> Agents -> Add Agent -> `warden-alerts`.
   (If only a draft exists and it is not listed, publish it from the agent page, or run `guild agent save --message "..." --publish` in `warden-alerts/`.)
   Grant the agent the Slack credential when prompted (Access & setup -> Credentials).
4. **Create the API trigger**: workspace `prowler-warden` -> Triggers -> Add Trigger -> **API**, pick agent `warden-alerts`, name it `warden`. Copy the `<key_id>:<key_secret>` string (shown once).
5. **Configure Warden** in `.env` (never commit):
   ```
   GUILD_API_URL=https://api.guild.ai/v1/workspaces/toni/prowler-warden/sessions
   GUILD_TRIGGER_KEY_ID=<key_id>
   GUILD_TRIGGER_KEY_SECRET=<key_secret>
   GUILD_SLACK_CHANNEL=#your-channel      # optional; default #warden-alerts
   ```
   (Check the owner/workspace segment in the trigger dialog or `guild workspace list`; the owner name is `toni`.)

## Test the trigger

```bash
curl -X POST "$GUILD_API_URL" \
  -u "$GUILD_TRIGGER_KEY_ID:$GUILD_TRIGGER_KEY_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"session_type":"api_trigger","agent_input":{
    "action_kind":"self-fix","severity":"high","check_id":"ec2_securitygroup_allow_ingress_from_internet_to_any_port",
    "resource":"sg-0123456789abcdef0","account":"123456789012","summary":"Closed 0.0.0.0/0 ingress",
    "status":"fixed-verified","mode":"auto","framework":"cis_5.0_aws","channel":"#warden-alerts"}}'
```
Expect HTTP 201 with a `session_url`; open it to watch the agent run. Or from Python:
`PYTHONPATH=src python -c "from warden import notify; print(notify.send_action({'action_kind':'detection','check_id':'x','resource':'r','account':'1','summary':'s','status':'detected'}))"`

## Notes
- Warden calls only fire for kinds `self-fix`/`pr` with status in fixed-verified, fix-applied-still-failing, failed, pr-opened, pr-ready, dry-run (see `_notify` in `src/warden/remediate.py`). Failures never affect remediation.
- Tests: `PYTHONPATH=src python tests/test_notify.py` (or pytest if installed).
