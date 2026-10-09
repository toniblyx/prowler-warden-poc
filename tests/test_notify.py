import json
from unittest import mock

from warden import notify

P = {"action_kind": "self-fix", "severity": "high", "check_id": "c", "resource": "r", "account": "1",
     "summary": "s", "status": "fixed-verified", "pr_url": None, "mode": "auto", "framework": "cis"}


def test_build_body_drops_empty_and_wraps(monkeypatch):
    monkeypatch.delenv("GUILD_SLACK_CHANNEL", raising=False)
    b = notify.build_body(P)
    assert b["session_type"] == "api_trigger"
    assert "pr_url" not in b["agent_input"] and b["agent_input"]["check_id"] == "c"


def test_build_body_bad_kind_and_channel(monkeypatch):
    monkeypatch.setenv("GUILD_SLACK_CHANNEL", "#x")
    b = notify.build_body({**P, "action_kind": "weird"})
    assert b["agent_input"]["action_kind"] == "detection" and b["agent_input"]["channel"] == "#x"


def test_not_configured(monkeypatch):
    for k in ("GUILD_API_URL", "GUILD_TRIGGER_KEY_ID", "GUILD_TRIGGER_KEY_SECRET"):
        monkeypatch.delenv(k, raising=False)
    assert notify.send_action(P) == {"sent": False, "reason": "not configured"}


def test_failure_never_raises(monkeypatch):
    monkeypatch.setenv("GUILD_API_URL", "http://127.0.0.1:1/x")
    monkeypatch.setenv("GUILD_TRIGGER_KEY_ID", "id")
    monkeypatch.setenv("GUILD_TRIGGER_KEY_SECRET", "sec")
    r = notify.send_action(P)
    assert r["sent"] is False and "error" in r


def test_success_basic_auth(monkeypatch):
    monkeypatch.setenv("GUILD_API_URL", "https://example.test/s")
    monkeypatch.setenv("GUILD_TRIGGER_KEY_ID", "id")
    monkeypatch.setenv("GUILD_TRIGGER_KEY_SECRET", "sec")
    resp = mock.MagicMock()
    resp.__enter__.return_value = resp
    resp.read.return_value = json.dumps({"session_url": "u"}).encode()
    resp.status = 201
    with mock.patch("urllib.request.urlopen", return_value=resp) as uo:
        r = notify.send_action(P)
    assert r["sent"] and r["session_url"] == "u"
    assert uo.call_args[0][0].headers["Authorization"].startswith("Basic ")


if __name__ == "__main__":  # run without pytest: PYTHONPATH=src python tests/test_notify.py
    import os

    class MP:
        def setenv(self, k, v): os.environ[k] = v
        def delenv(self, k, raising=True): os.environ.pop(k, None)

    class MockPatch:  # monkeypatch stand-in
        pass
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(MP()) if fn.__code__.co_argcount else fn()
            print("ok", name)
