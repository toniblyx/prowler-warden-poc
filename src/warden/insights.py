"""Account overview, annotated posture timeline and fix simulator. Everything is computed from ClickHouse."""
from datetime import datetime, timezone

from . import db, frameworks, remediate

CODE_SERVICES = {"ec2", "s3", "rds", "vpc", "kms", "cloudtrail", "cloudwatch", "config", "ebs", "elb", "elbv2", "sns", "sqs", "awslambda", "ecr", "efs"}
SEV_ORDER = ["critical", "high", "medium", "low"]


def route(check_id: str) -> str:
    """How a failing check can be fixed: 'auto' (safe runtime fix), 'pr' (Terraform change), 'manual' (needs a human)."""
    if check_id in remediate.REMEDIATORS:
        return "auto"
    if check_id.split("_")[0] in CODE_SERVICES:
        return "pr"
    return "manual"


def _naive_utc_offset():
    """Findings are stored with naive datetimes that ClickHouse read as server-local time; undo that for display."""
    return datetime.now().astimezone().utcoffset()


def _true_utc(dt: datetime) -> str:
    return (dt + _naive_utc_offset()).replace(tzinfo=None).isoformat() + "Z"


def account_summary(account: str, framework: str) -> dict:
    latest = """(check_id, scan_time) IN (SELECT check_id, max(scan_time) FROM findings WHERE account_id={a:String} GROUP BY check_id)"""
    res = db.query(f"""SELECT service, uniqExact(resource_uid) AS resources, uniqExactIf(resource_uid, status='FAIL') AS failing
                       FROM findings WHERE account_id={{a:String}} AND {latest} AND resource_uid != '' GROUP BY service ORDER BY resources DESC LIMIT 8""", {"a": account})
    sev = db.query(f"""SELECT severity, uniqExact((check_id, resource_uid)) AS n FROM findings WHERE account_id={{a:String}} AND {latest} AND status='FAIL' GROUP BY severity""", {"a": account})
    tot = db.query(f"SELECT uniqExact(resource_uid) AS n FROM findings WHERE account_id={{a:String}} AND {latest} AND resource_uid != ''", {"a": account})[0]["n"]
    cost = db.query("""WITH (SELECT max(day) FROM cost_daily WHERE account_id={a:String}) AS md
                       SELECT round(sumIf(amount, day > md - 30), 2) AS d30, round(sumIf(amount, day = md), 2) AS today FROM cost_daily WHERE account_id={a:String}""", {"a": account})
    top = db.query("""SELECT service, round(sum(amount), 2) AS amt FROM cost_daily WHERE account_id={a:String} AND day > (SELECT max(day) FROM cost_daily WHERE account_id={a:String}) - 30
                      GROUP BY service ORDER BY amt DESC LIMIT 3""", {"a": account})
    ev = db.query("SELECT count() AS n, countIf(read_only=0) AS w FROM cloudtrail_events WHERE account_id={a:String} AND event_time > now() - INTERVAL 1 HOUR", {"a": account})[0]
    scans = db.query("SELECT count() AS n, max(scan_time) AS last FROM scans WHERE account_id={a:String} AND source != 'synthetic'", {"a": account})[0]
    return {"account": account, "resources": tot, "by_service": res, "failing_by_severity": {r["severity"]: r["n"] for r in sev},
            "cost_30d": cost[0]["d30"] if cost else None, "cost_today": cost[0]["today"] if cost else None, "top_services": top,
            "events_hour": ev["n"], "changes_hour": ev["w"], "scans": scans["n"], "last_scan": _true_utc(scans["last"]) if scans["n"] else None}


def timeline(account: str, framework: str) -> dict:
    """Compliance % at each moment a check result changed, plus markers for detections and actions."""
    rows = db.query("SELECT check_id, scan_time, max(status = 'FAIL') AS fail FROM findings WHERE account_id={a:String} GROUP BY check_id, scan_time ORDER BY scan_time", {"a": account})
    fm = {}
    for r in db.query("SELECT req_id, check_id, manual FROM framework_map WHERE framework={f:String} AND check_id != ''", {"f": framework}):
        fm.setdefault(r["req_id"], []).append(r["check_id"])
    by_check = {}
    for r in rows:
        by_check.setdefault(r["check_id"], []).append((r["scan_time"], bool(r["fail"])))
    times = sorted({r["scan_time"] for r in rows})
    merged = []
    for t in times:  # merge near-simultaneous scans so one scan = one point
        if not merged or (t - merged[-1]).total_seconds() > 90:
            merged.append(t)
    pts = []
    for t in merged:
        status = {}
        for c, seq in by_check.items():
            last = [x for x in seq if x[0] <= t]
            if last:
                status[c] = last[-1][1]
        graded = passed = 0
        for checks in fm.values():
            known = [status[c] for c in checks if c in status]
            if known:
                graded += 1
                passed += not any(known)
        if graded:
            pts.append({"t": _true_utc(t), "pct": round(100 * passed / graded, 1), "graded": graded})
    marks = []
    for d in db.query("SELECT event_time, severity, title, status, resource FROM detections FINAL WHERE account_id={a:String} ORDER BY event_time", {"a": account}):
        marks.append({"t": d["event_time"].isoformat() + "Z", "kind": "detection", "label": f"{d['title']} ({d['status']})", "sev": d["severity"]})
    for a in db.query("SELECT ts, kind, status, summary FROM actions FINAL WHERE account_id={a:String} AND kind IN ('self-fix','pr') ORDER BY ts", {"a": account}):
        marks.append({"t": a["ts"].isoformat() + "Z", "kind": "fix" if a["kind"] == "self-fix" else "pr", "label": f"{a['status']}: {a['summary'][:80]}"})
    return {"points": pts, "marks": marks, "projection": simulate(account, framework)["scenarios"]}


def simulate(account: str, framework: str) -> dict:
    """What compliance would be if each class of fix were applied. Requirements flip to PASS only when every failing check in them is fixed."""
    reqs = db.query("""
    SELECT m.req_id AS req_id, any(m.section) AS section, groupUniqArrayIf(m.check_id, f.status = 'FAIL') AS failing_checks,
           countIf(f.status = 'PASS') AS passing, any(m.manual) AS manual
    FROM framework_map AS m LEFT JOIN (SELECT check_id, status FROM findings WHERE account_id = {a:String}
         AND (check_id, scan_time) IN (SELECT check_id, max(scan_time) FROM findings WHERE account_id = {a:String} GROUP BY check_id)) AS f ON f.check_id = m.check_id
    WHERE m.framework = {f:String} GROUP BY m.req_id""", {"a": account, "f": framework})
    graded = [r for r in reqs if r["manual"] == 0 and (r["failing_checks"] or r["passing"])]
    failing = [r for r in graded if r["failing_checks"]]
    base_pass = len(graded) - len(failing)

    def pct(allowed):
        flipped = sum(all(route(c) in allowed for c in r["failing_checks"]) for r in failing)
        return round(100 * (base_pass + flipped) / len(graded), 1) if graded else None, flipped

    now, _ = pct(set())
    a, fa = pct({"auto"})
    ap, fap = pct({"auto", "pr"})
    full, ff = pct({"auto", "pr", "manual"})
    counts = db.query("""SELECT check_id, any(severity) AS severity, uniqExact(resource_uid) AS resources FROM findings WHERE account_id={a:String} AND status='FAIL'
        AND (check_id, scan_time) IN (SELECT check_id, max(scan_time) FROM findings WHERE account_id={a:String} GROUP BY check_id)
        AND check_id IN (SELECT check_id FROM framework_map WHERE framework={f:String}) GROUP BY check_id""", {"a": account, "f": framework})
    owner = {}
    for r in failing:
        for c in r["failing_checks"]:
            owner.setdefault(c, []).append(r["req_id"])
    plan = []
    for c in counts:
        chk = c["check_id"]
        meta = frameworks.check_metadata(chk)
        solo = [rid for rid in owner.get(chk, []) if all(x == chk for x in next(r for r in failing if r["req_id"] == rid)["failing_checks"])]
        plan.append({"check_id": chk, "severity": c["severity"], "resources": c["resources"], "route": route(chk), "title": meta.get("CheckTitle", chk),
                     "requirements": sorted(owner.get(chk, [])), "unlocks": len(solo),
                     "effect": EFFECT.get(chk, "Fix in Terraform via PR" if route(chk) == "pr" else "Needs a person (console or policy decision)" if route(chk) == "manual" else "")})
    plan.sort(key=lambda p: (-p["unlocks"], SEV_ORDER.index(p["severity"]) if p["severity"] in SEV_ORDER else 9, -p["resources"]))
    return {"scenarios": [{"key": "now", "label": "Today", "pct": now, "fixed": 0}, {"key": "auto", "label": "+ self-fix", "pct": a, "fixed": fa},
                          {"key": "pr", "label": "+ PRs to code", "pct": ap, "fixed": fap}, {"key": "all", "label": "+ human tasks", "pct": full, "fixed": ff}],
            "graded": len(graded), "failing": len(failing), "plan": plan[:40]}


EFFECT = {
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": "Revoke 0.0.0.0/0 on port 22 (undo recorded)",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389": "Revoke 0.0.0.0/0 on port 3389 (undo recorded)",
    "ec2_securitygroup_allow_ingress_from_internet_to_any_port": "Revoke open-to-internet ingress (undo recorded)",
    "s3_bucket_level_public_access_block": "Enable all four public access block settings on the bucket",
    "s3_account_level_public_access_blocks": "Enable account-wide public access block (could break intentionally public buckets)",
    "cloudtrail_multi_region_enabled": "Start logging on the trail",
    "ec2_ebs_default_encryption": "Encrypt new EBS volumes by default (existing volumes unchanged)",
    "rds_instance_no_public_access": "Set PubliclyAccessible=false (undo recorded)",
}


def open_findings(account: str, framework: str, limit: int = 400) -> list[dict]:
    """Every failing resource from the newest result of each check, with how it can be fixed and any exploitability evidence."""
    from . import signals
    rows = db.query("""
    SELECT check_id, resource_uid, region, any(severity) AS severity, any(service) AS service, any(status_extended) AS detail
    FROM findings WHERE account_id={a:String} AND status = 'FAIL'
      AND (check_id, scan_time) IN (SELECT check_id, max(scan_time) FROM findings WHERE account_id={a:String} GROUP BY check_id)
      AND check_id IN (SELECT check_id FROM framework_map WHERE framework={f:String})
    GROUP BY check_id, resource_uid, region""", {"a": account, "f": framework})
    reqs = {}
    for r in db.query("SELECT check_id, groupUniqArray(req_id) AS reqs FROM framework_map WHERE framework={f:String} GROUP BY check_id", {"f": framework}):
        reqs[r["check_id"]] = sorted(r["reqs"])
    verdict = {p["check_id"]: p for p in signals.prioritize(account, framework, 500)}
    flagged = {d["resource"] for d in db.query("SELECT resource FROM detections FINAL WHERE account_id={a:String} AND status = 'violation'", {"a": account}) if d["resource"]}
    out = []
    for r in rows:
        v = verdict.get(r["check_id"], {})
        out.append({"check_id": r["check_id"], "title": frameworks.check_metadata(r["check_id"]).get("CheckTitle", r["check_id"]), "severity": r["severity"],
                    "service": r["service"], "resource": r["resource_uid"], "region": r["region"], "reqs": reqs.get(r["check_id"], []),
                    "route": route(r["check_id"]), "effect": EFFECT.get(r["check_id"], ""), "verdict": v.get("verdict", "misconfigured-only"), "evidence": v.get("evidence", []),
                    "seen_in_cloudtrail": any(f and f in r["resource_uid"] for f in flagged)})
    out.sort(key=lambda x: (SEV_ORDER.index(x["severity"]) if x["severity"] in SEV_ORDER else 9, {"auto": 0, "pr": 1, "manual": 2}[x["route"]], x["check_id"]))
    return out[:limit]
