"""Send Warden action alerts to a Guild.ai API trigger (agent `warden-alerts` -> Slack).

Env: GUILD_API_URL (full .../v1/workspaces/<owner>/<workspace>/sessions URL),
     GUILD_TRIGGER_KEY_ID, GUILD_TRIGGER_KEY_SECRET, optional GUILD_SLACK_CHANNEL.
Never raises. Unset vars -> dry-run (log only).
"""
import base64
import json
import logging
import os
import urllib.request

log = logging.getLogger("warden.notify")
TIMEOUT = 10
KINDS = {"self-fix", "pr", "detection"}


def build_body(payload: dict) -> dict:
    """Wrap the action payload as a Guild api_trigger session request, dropping empty values."""
    inp = {k: v for k, v in payload.items() if v not in (None, "")}
    if inp.get("action_kind") not in KINDS:
        inp["action_kind"] = "detection"
    ch = os.environ.get("GUILD_SLACK_CHANNEL")
    if ch and "channel" not in inp:
        inp["channel"] = ch
    return {"session_type": "api_trigger", "agent_input": inp}


def _config():
    url, kid, sec = (os.environ.get(k, "") for k in ("GUILD_API_URL", "GUILD_TRIGGER_KEY_ID", "GUILD_TRIGGER_KEY_SECRET"))
    return (url, kid, sec) if url and kid and sec else None


def send_action(payload: dict) -> dict:
    try:
        body = build_body(payload)
        cfg = _config()
        if not cfg:
            log.info("notify (not configured): %s", json.dumps(body["agent_input"], default=str)[:500])
            return {"sent": False, "reason": "not configured"}
        url, kid, sec = cfg
        auth = base64.b64encode(f"{kid}:{sec}".encode()).decode()
        req = urllib.request.Request(url, data=json.dumps(body, default=str).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.loads(r.read().decode() or "{}")
        return {"sent": True, "status": r.status, "session_url": data.get("session_url")}
    except Exception as e:  # never break remediation because of a notification
        log.warning("notify failed: %s", e)
        return {"sent": False, "error": str(e)[:200]}
