import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import agent, compliance, db

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
