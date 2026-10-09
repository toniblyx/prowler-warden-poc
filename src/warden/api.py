import os
import threading
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import agent, cloudtrail, compliance, db, policy, signals

app = FastAPI(title="Warden")
STATIC = Path(__file__).parent / "static"


def timed(fn, *a):
    t = time.perf_counter()
    out = fn(*a)
    return {"data": out, "ms": round((time.perf_counter() - t) * 1000, 1)}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/accounts")
def accounts():
    return timed(compliance.accounts)


@app.get("/api/overview")
def overview(account: str, framework: str):
    t = time.perf_counter()
    reqs = compliance.requirements(account, framework)
    out = {"score": compliance.score(reqs), "requirements": reqs, "trend": compliance.trend(account, framework),
           "drift": compliance.drift(account, framework, 50), "top": compliance.top_failing_checks(account, framework),
           "rows": db.query("SELECT count() AS n FROM findings")[0]["n"]}
    out["ms"] = round((time.perf_counter() - t) * 1000, 1)
    return JSONResponse(content=__import__("json").loads(__import__("json").dumps(out, default=str)))


class Review(BaseModel):
    account: str
    framework: str
    prompt: str = "Review drift since the previous scan and propose remediations."


@app.post("/api/review")
def review(r: Review):
    events = []
    try:
        text = agent.run(r.prompt, r.account, r.framework, on_event=lambda n, i: events.append(n))
    except Exception as e:
        return {"error": str(e), "tools": events}
    return {"report": text, "tools": events}


@app.get("/api/proposals")
def proposals():
    return db.query("SELECT toString(id) AS id, ts, status, check_id, resource_uid, summary, command FROM actions FINAL ORDER BY ts DESC LIMIT 50")


@app.get("/api/policy")
def get_policy():
    return policy.get()


class PolicySet(BaseModel):
    key: str
    value: str | bool | list[str]


@app.post("/api/policy")
def set_policy(p: PolicySet):
    try:
        return policy.set_(p.key, p.value)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/detections")
def detections():
    return db.query("SELECT id, event_time, severity, rule_id, title, actor, resource, region, req_ids, status, note "
                    "FROM detections FINAL ORDER BY event_time DESC LIMIT 25")


@app.get("/api/actions")
def actions():
    return db.query("SELECT toString(id) AS id, ts, kind, status, check_id, resource_uid, summary FROM actions FINAL ORDER BY ts DESC LIMIT 25")


@app.get("/api/signals")
def get_signals(account: str, framework: str):
    return {"anomalies": signals.cost_anomalies(account), "ranked": signals.prioritize(account, framework, 10)}


WATCH = {"on": os.getenv("WARDEN_WATCH") == "1", "last": None, "error": None}


def _watch_loop():
    while True:
        if WATCH["on"]:
            try:
                WATCH["last"] = cloudtrail.cycle(os.getenv("WARDEN_ACCOUNT", ""), os.getenv("WARDEN_FRAMEWORK", "cis_5.0_aws"),
                                                 os.getenv("WARDEN_PROFILE") or None, os.getenv("WARDEN_REGION", "us-east-1"))
                WATCH["error"] = None
            except Exception as e:
                WATCH["error"] = str(e)[:200]
        time.sleep(20)


threading.Thread(target=_watch_loop, daemon=True).start()


@app.get("/api/watch")
def watch_state():
    return WATCH


@app.post("/api/watch/{on}")
def watch_set(on: bool):
    WATCH["on"] = on
    return WATCH


@app.get("/api/live")
def live_status():
    from . import live_demo
    return live_demo.status()


@app.post("/api/live/start")
def live_start():
    from . import live_demo
    return live_demo.start()


@app.post("/api/live/reset")
def live_reset():
    from . import live_demo
    return live_demo.reset()


@app.post("/api/actions/{action_id}/revert")
def revert_action(action_id: str):
    from . import config, remediate
    return remediate.revert(action_id, config.PROFILE, config.REGION)
