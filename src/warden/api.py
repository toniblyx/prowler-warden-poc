import os
import threading
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import agent, cloudtrail, compliance, db, frameworks, policy, runner, signals

app = FastAPI(title="Warden")
STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")


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
    reqs = compliance.posture(account, framework)
    cov = compliance.coverage(account).get(framework, {"total": 0, "scanned": 0})
    out = {"coverage": cov, "job": JOBS.get((account, framework)), "score": compliance.score(reqs), "requirements": reqs, "trend": compliance.trend(account, framework),
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
def detections(framework: str = ""):
    rows = db.query("SELECT id, event_time, severity, rule_id, title, actor, resource, region, req_ids, check_ids, status, note "
                    "FROM detections FINAL ORDER BY event_time DESC LIMIT 25")
    if framework:  # requirements are derived for the framework selected in the UI, not the one active at detection time
        cm = {r["check_id"]: r["reqs"] for r in db.query("SELECT check_id, groupUniqArray(req_id) AS reqs FROM framework_map WHERE framework={f:String} GROUP BY check_id", {"f": framework})}
        for r in rows:
            r["req_ids"] = sorted({q for c in r.get("check_ids", []) for q in cm.get(c, [])}) if "check_ids" in r else r["req_ids"]
    return rows


@app.get("/api/actions")
def actions():
    return db.query("SELECT toString(id) AS id, ts, kind, status, check_id, resource_uid, summary, command FROM actions FINAL ORDER BY ts DESC LIMIT 25")


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
        time.sleep(10)


threading.Thread(target=_watch_loop, daemon=True).start()
threading.Thread(target=runner.ensure_frameworks, daemon=True).start()


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


@app.get("/api/frameworks")
def frameworks_list(account: str):
    cov = compliance.coverage(account)
    out = []
    for f in frameworks.list_frameworks():
        c = cov.get(f, {"total": 0, "scanned": 0})
        out.append({**frameworks.display(f), "total": c["total"], "scanned": c["scanned"]})
    return sorted(out, key=lambda x: (-(x["scanned"] > 0), x["name"]))


JOBS: dict = {}


class ScanReq(BaseModel):
    account: str
    framework: str


@app.post("/api/scan")
def start_scan(r: ScanReq):
    key = (r.account, r.framework)
    if JOBS.get(key, {}).get("status") == "running":
        return JOBS[key]
    JOBS[key] = {"status": "running", "started": time.time(), "error": None}

    def run():
        try:
            runner.scan(r.framework, os.getenv("WARDEN_PROFILE") or None, [os.getenv("WARDEN_REGION", "us-east-1")], None)
            JOBS[key].update(status="done")
        except Exception as e:
            JOBS[key].update(status="error", error=str(e)[:200])
    threading.Thread(target=run, daemon=True).start()
    return JOBS[key]


@app.get("/api/events")
def events(limit: int = 80, writes: bool = False):
    where = "AND read_only = 0" if writes else ""
    rows = db.query(f"""
    SELECT e.event_id AS event_id, e.event_time AS event_time, e.event_name AS event_name, e.event_source AS event_source,
           e.user_type AS user_type, e.user_arn AS user_arn, e.source_ip AS source_ip, e.region AS region, e.error_code AS error_code,
           e.read_only AS read_only, d.rule_id AS rule_id, d.severity AS severity, d.status AS verdict
    FROM (SELECT * FROM cloudtrail_events WHERE event_time > now() - INTERVAL 1 DAY {where} ORDER BY event_time DESC LIMIT {int(limit)}) AS e
    LEFT JOIN (SELECT event_id, any(rule_id) AS rule_id, any(severity) AS severity, argMax(status, ts) AS status FROM detections GROUP BY event_id) AS d
      ON d.event_id = e.event_id ORDER BY e.event_time DESC""")
    stats = db.query("SELECT count() AS n, countIf(read_only = 0) AS writes FROM cloudtrail_events WHERE event_time > now() - INTERVAL 1 HOUR")[0]
    return {"events": rows, "last_hour": stats, "now": time.time()}
