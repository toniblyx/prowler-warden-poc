"""Compliance posture + drift, computed in ClickHouse."""
from . import db

_SCAN = """(SELECT scan_id FROM scans WHERE account_id = {{a:String}} AND framework = {{f:String}}
            ORDER BY scan_time DESC LIMIT 1 OFFSET {off})"""


def scans(account: str, framework: str, limit: int = 20) -> list[dict]:
    return db.query("SELECT scan_id, scan_time, findings FROM scans WHERE account_id={a:String} AND framework={f:String} "
                    f"ORDER BY scan_time DESC LIMIT {int(limit)}", {"a": account, "f": framework})


def requirements(account: str, framework: str, offset: int = 0) -> list[dict]:
    """Per-requirement status for one scan (offset 0 = latest)."""
    sql = f"""
    SELECT m.req_id AS req_id, any(m.section) AS section, any(m.description) AS description,
           any(m.manual) AS manual, countIf(f.status = 'FAIL') AS failing, countIf(f.status = 'PASS') AS passing,
           groupUniqArrayIf(m.check_id, f.status = 'FAIL') AS failing_checks,
           multiIf(any(m.manual) = 1, 'MANUAL', countIf(f.status = 'FAIL') > 0, 'FAIL',
                   countIf(f.status = 'PASS') > 0, 'PASS', 'NO_DATA') AS status
    FROM framework_map AS m
    LEFT JOIN (SELECT check_id, status FROM findings WHERE scan_id IN {_SCAN.format(off=int(offset))}) AS f
      ON f.check_id = m.check_id
    WHERE m.framework = {{f:String}}
    GROUP BY m.req_id ORDER BY m.req_id"""
    return db.query(sql, {"a": account, "f": framework})


def score(reqs: list[dict]) -> dict:
    graded = [r for r in reqs if r["status"] in ("PASS", "FAIL")]
    p = sum(r["status"] == "PASS" for r in graded)
    return {"pass": p, "fail": len(graded) - p, "graded": len(graded),
            "manual": sum(r["status"] == "MANUAL" for r in reqs),
            "no_data": sum(r["status"] == "NO_DATA" for r in reqs),
            "pct": round(100 * p / len(graded), 1) if graded else None}


def trend(account: str, framework: str, limit: int = 30) -> list[dict]:
    """Compliance % per scan (requirement-level), oldest first."""
    sql = """
    SELECT scan_id, any(scan_time) AS scan_time,
           round(100 * countIf(req_fail = 0) / count(), 1) AS pct, countIf(req_fail > 0) AS failing_reqs
    FROM (
      SELECT s.scan_id AS scan_id, s.scan_time AS scan_time, m.req_id AS req_id,
             countIf(f.status = 'FAIL') AS req_fail
      FROM (SELECT scan_id, scan_time FROM scans WHERE account_id={a:String} AND framework={f:String}
            ORDER BY scan_time DESC LIMIT %d) AS s
      INNER JOIN (SELECT scan_id, check_id, status FROM findings WHERE account_id={a:String}) AS f ON f.scan_id = s.scan_id
      INNER JOIN (SELECT req_id, check_id FROM framework_map WHERE framework={f:String} AND manual = 0) AS m
        ON m.check_id = f.check_id
      GROUP BY s.scan_id, s.scan_time, m.req_id)
    GROUP BY scan_id ORDER BY scan_time""" % int(limit)
    return db.query(sql, {"a": account, "f": framework})


def drift(account: str, framework: str, limit: int = 200) -> dict:
    """Resource-level diff between the latest scan and the one before it, limited to framework checks."""
    cur, prev = _SCAN.format(off=0), _SCAN.format(off=1)
    base = f"""
    SELECT check_id, resource_uid, region, any(severity) AS severity, any(status_extended) AS detail,
           (SELECT groupUniqArray(req_id) FROM framework_map WHERE framework={{f:String}} AND check_id = x.check_id) AS reqs
    FROM findings AS x
    WHERE scan_id IN {{side}} AND status = 'FAIL' AND check_id IN (SELECT check_id FROM framework_map WHERE framework={{f:String}})
      AND (check_id, resource_uid, region) NOT IN
          (SELECT check_id, resource_uid, region FROM findings WHERE scan_id IN {{other}} AND status = 'FAIL')
    GROUP BY check_id, resource_uid, region
    ORDER BY multiIf(severity='critical',0,severity='high',1,severity='medium',2,3) LIMIT {int(limit)}"""
    reg = db.query(base.replace("{side}", cur).replace("{other}", prev), {"a": account, "f": framework})
    res = db.query(base.replace("{side}", prev).replace("{other}", cur), {"a": account, "f": framework})
    return {"regressions": reg, "resolved": res}


def top_failing_checks(account: str, framework: str, limit: int = 15) -> list[dict]:
    sql = f"""
    SELECT check_id, any(severity) AS severity, count() AS failing_resources
    FROM findings WHERE scan_id IN {_SCAN.format(off=0)} AND status='FAIL'
      AND check_id IN (SELECT check_id FROM framework_map WHERE framework={{f:String}})
    GROUP BY check_id ORDER BY multiIf(severity='critical',0,severity='high',1,severity='medium',2,3), failing_resources DESC
    LIMIT {int(limit)}"""
    return db.query(sql, {"a": account, "f": framework})


def accounts() -> list[dict]:
    return db.query("SELECT account_id, framework, count() AS scans, max(scan_time) AS last_scan FROM scans GROUP BY account_id, framework")
