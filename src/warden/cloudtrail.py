"""CloudTrail -> ClickHouse, rule detections, and event-driven verification with Prowler."""
import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

from . import db, frameworks, remediate, rules, runner

EVENT_COLS = ["event_id", "event_time", "account_id", "region", "event_source", "event_name", "user_type", "user_arn",
              "source_ip", "error_code", "read_only", "mfa_used", "request_params", "raw"]
DET_COLS = ["id", "event_id", "event_time", "account_id", "region", "rule_id", "title", "severity", "actor", "resource",
            "check_ids", "req_ids", "status", "note"]


def normalize(ct: dict) -> dict:
    """CloudTrail record (the JSON inside LookupEvents' CloudTrailEvent, or a log-file record) -> row dict."""
    ui = ct.get("userIdentity") or {}
    t = ct["eventTime"].replace("Z", "+00:00")
    return {
        "event_id": ct["eventID"], "event_time": datetime.fromisoformat(t).astimezone(timezone.utc),
        "account_id": ct.get("recipientAccountId") or ui.get("accountId", ""), "region": ct.get("awsRegion", ""),
        "event_source": ct.get("eventSource", ""), "event_name": ct["eventName"], "user_type": ui.get("type", ""),
        "user_arn": ui.get("arn", ""), "source_ip": ct.get("sourceIPAddress", ""), "error_code": ct.get("errorCode", ""),
        "read_only": int(bool(ct.get("readOnly"))), "mfa_used": (ct.get("additionalEventData") or {}).get("MFAUsed", ""),
        "params": ct.get("requestParameters") or {}, "raw": json.dumps(ct, separators=(",", ":")),
    }


def store(events: list[dict]):
    c = db.init()
    if events:
        c.insert("cloudtrail_events", [[e[k] if k != "request_params" else json.dumps(e["params"]) for k in EVENT_COLS] for e in events],
                 column_names=EVENT_COLS)


def detect(events: list[dict], framework: str) -> list[dict]:
    """Run the rules; attach framework requirements; store detections as status=new."""
    c = db.init()
    reqs = {}
    for r in db.query("SELECT check_id, groupUniqArray(req_id) AS reqs FROM framework_map WHERE framework={f:String} GROUP BY check_id", {"f": framework}):
        reqs[r["check_id"]] = r["reqs"]
    out = []
    for e in events:
        for h in rules.evaluate(e):
            did = hashlib.sha1(f"{e['event_id']}:{h.rule_id}".encode()).hexdigest()[:16]
            out.append({"id": did, "event_id": e["event_id"], "event_time": e["event_time"], "account_id": e["account_id"],
                        "region": e["region"], "rule_id": h.rule_id, "title": h.title, "severity": h.severity,
                        "actor": e["user_arn"] or e["user_type"], "resource": h.resource, "check_ids": h.checks,
                        "req_ids": sorted({r for ck in h.checks for r in reqs.get(ck, [])}), "status": "new", "note": ""})
    if out:
        c.insert("detections", [[d[k] for k in DET_COLS] for d in out], column_names=DET_COLS)
    return out


def verify(det: dict, profile: str | None) -> dict:
    """Targeted Prowler run on the affected checks/region: did the API call actually leave us non-compliant?"""
    from pathlib import Path
    region = det["region"] if det["region"] and not det["region"].startswith("us-east-1") or det["region"] == "us-east-1" else None
    path = runner.run_prowler_checks(det["check_ids"], profile, [region] if region else None)
    rows = runner.parse_ocsf(path, f"verify-{det['id']}")
    runner.ingest_findings_only(rows)
    failing = [r for r in rows if r[7] == "FAIL"]
    if det["resource"]:  # narrow to the touched resource when we know it
        hit = [r for r in failing if det["resource"] in r[8] or det["resource"] in r[9]]
        failing = hit  # only the resource the event touched; never broaden to unrelated failures
    status = "violation" if failing else "compliant"
    note = (f"{len(failing)} failing resource(s): " + "; ".join(f"{r[4]} {r[8]}" for r in failing[:5])) if failing else "Prowler re-check passed"
    c = db.client()
    c.insert("detections", [[det[k] if k not in ("status", "note") else {"status": status, "note": note}[k] for k in DET_COLS]],
             column_names=DET_COLS)
    return {"id": det["id"], "status": status, "note": note, "detection": det,
            "failing": [{"check_id": r[4], "resource_uid": r[8], "region": r[3]} for r in failing]}


WATERMARK: dict = {}


def poll(account: str, profile: str | None, region: str = "us-east-1", since_minutes: int = 15, write_only: bool = False) -> list[dict]:
    """Pull management events via LookupEvents (works with or without a configured trail), newest first."""
    sess = boto3.Session(profile_name=profile, region_name=region)
    ct = sess.client("cloudtrail")
    start = WATERMARK.get((account, region)) or (datetime.now(timezone.utc) - timedelta(minutes=since_minutes))
    poll_started = datetime.now(timezone.utc)
    start = min(start, poll_started - timedelta(seconds=1))
    kw = {"StartTime": start, "EndTime": poll_started, "MaxResults": 50}
    if write_only:
        kw["LookupAttributes"] = [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}]
    events = []
    for page in ct.get_paginator("lookup_events").paginate(**kw):
        for ev in page["Events"]:
            events.append(normalize(json.loads(ev["CloudTrailEvent"])))
    WATERMARK[(account, region)] = poll_started - timedelta(minutes=10)  # CloudTrail delivers late; overlap and dedupe by event id
    return events


def cycle(account: str, framework: str, profile: str | None, region: str = "us-east-1", verify_hits: bool = True) -> dict:
    evs = poll(account, profile, region)
    if evs:
        seen = {r["event_id"] for r in db.query("SELECT event_id FROM cloudtrail_events WHERE event_id IN {ids:Array(String)}",
                                                {"ids": [e["event_id"] for e in evs]})}
        evs = [e for e in evs if e["event_id"] not in seen]
    store(evs)
    dets = detect(evs, framework)
    verified = [verify(d, profile) for d in dets] if verify_hits else []
    handled = [remediate.handle(v, framework, profile) for v in verified if v["status"] == "violation"]
    return {"events": len(evs), "detections": len(dets), "verified": [{k: v[k] for k in ("id", "status", "note")} for v in verified],
            "remediation": handled}


def watch(account: str, framework: str, profile: str | None, region: str = "us-east-1", every: int = 60, on_cycle=print):
    while True:
        try:
            on_cycle(cycle(account, framework, profile, region))
        except Exception as e:  # keep monitoring through throttling / expired sessions
            on_cycle({"error": str(e)})
        time.sleep(every)
