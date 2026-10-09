"""Exploitability signals: cost anomalies + suspicious CloudTrail activity, correlated with failing compliance checks.

Compliance says what is misconfigured. These signals say whether someone may be using it. Cost is a lagging, noisy
signal (Cost Explorer lags ~24h), so it raises priority; it is evidence to investigate, not proof of compromise."""
from datetime import date, timedelta

import boto3

from . import db

# Cost Explorer service name -> Prowler service prefixes whose failures that spend could be exploiting
SERVICE_CHECKS = {
    "Amazon Elastic Compute Cloud - Compute": ["ec2", "vpc", "ssm"], "EC2 - Other": ["ec2", "vpc"],
    "Amazon Simple Storage Service": ["s3"], "AWS Lambda": ["awslambda", "iam"], "Amazon Relational Database Service": ["rds"],
    "Amazon SageMaker": ["sagemaker", "iam"], "Amazon Bedrock": ["bedrock", "iam"], "Amazon Elastic Container Service": ["ecs", "ecr", "iam"],
    "Amazon Virtual Private Cloud": ["vpc", "ec2"], "AWS Key Management Service": ["kms"], "Amazon CloudFront": ["cloudfront", "s3"],
}
SEV_W = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def fetch_costs(account: str, profile: str | None, days: int = 30) -> int:
    ce = boto3.Session(profile_name=profile, region_name="us-east-1").client("ce")  # one request (~$0.01)
    end = date.today() + timedelta(days=1)
    resp = ce.get_cost_and_usage(TimePeriod={"Start": str(end - timedelta(days=days)), "End": str(end)}, Granularity="DAILY",
                                 Metrics=["UnblendedCost"], GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}, {"Type": "DIMENSION", "Key": "REGION"}])
    rows = [[date.fromisoformat(d["TimePeriod"]["Start"]), account, g["Keys"][0], g["Keys"][1], float(g["Metrics"]["UnblendedCost"]["Amount"])]
            for d in resp["ResultsByTime"] for g in d["Groups"]]
    if rows:
        db.init().insert("cost_daily", rows, column_names=["day", "account_id", "service", "region", "amount"])
    return len(rows)


def cost_anomalies(account: str, min_ratio: float = 2.0, min_delta: float = 1.0, window: int = 14) -> list[dict]:
    """Latest days vs trailing baseline per (service, region), computed in ClickHouse."""
    return db.query(f"""
    WITH latest AS (SELECT max(day) AS d FROM cost_daily WHERE account_id={{a:String}})
    SELECT service, region, today, base, today - base AS delta, round(today / greatest(base, 0.01), 1) AS ratio,
           round((today - base) / greatest(sd, 0.05), 1) AS zscore
    FROM (
      SELECT service, region,
             sumIf(amount, day = (SELECT d FROM latest)) AS today,
             avgIf(amount, day < (SELECT d FROM latest) AND day >= (SELECT d FROM latest) - {int(window)}) AS base,
             stddevPopIf(amount, day < (SELECT d FROM latest) AND day >= (SELECT d FROM latest) - {int(window)}) AS sd
      FROM (SELECT day, account_id, service, region, amount FROM cost_daily UNION ALL SELECT day, account_id, service, region, amount FROM cost_demo) WHERE account_id={{a:String}} GROUP BY service, region)
    WHERE today - base >= {{md:Float64}} AND today / greatest(base, 0.01) >= {{mr:Float64}}
    ORDER BY delta DESC""", {"a": account, "md": min_delta, "mr": min_ratio})


def suspicious_activity(account: str, hours: int = 24) -> list[dict]:
    """CloudTrail patterns that suggest use, not just exposure."""
    return db.query(f"""
    SELECT 'root_usage' AS signal, event_source AS service, region, count() AS n, any(user_arn) AS actor
    FROM cloudtrail_events WHERE account_id={{a:String}} AND user_type='Root' AND event_time > now() - INTERVAL {int(hours)} HOUR
    GROUP BY event_source, region
    UNION ALL
    SELECT 'access_denied_burst', event_source, region, count(), any(user_arn)
    FROM cloudtrail_events WHERE account_id={{a:String}} AND error_code IN ('AccessDenied','UnauthorizedOperation','Client.UnauthorizedOperation')
      AND event_time > now() - INTERVAL {int(hours)} HOUR GROUP BY event_source, region HAVING count() >= 20
    UNION ALL
    SELECT 'external_ip_write', event_source, region, count(), any(user_arn)
    FROM cloudtrail_events WHERE account_id={{a:String}} AND read_only=0 AND user_type IN ('IAMUser','Root')
      AND NOT (source_ip LIKE '%.amazonaws.com') AND event_time > now() - INTERVAL {int(hours)} HOUR
      AND event_name IN ('RunInstances','CreateAccessKey','CreateUser','AttachUserPolicy','PutUserPolicy','CreateLoginProfile','AuthorizeSecurityGroupIngress')
    GROUP BY event_source, region
    UNION ALL
    SELECT 'recent_open_exposure', event_source, region, count(), any(user_arn) FROM cloudtrail_events
    WHERE account_id={{a:String}} AND event_name IN ('AuthorizeSecurityGroupIngress','PutBucketPolicy','ModifyDBInstance')
      AND event_time > now() - INTERVAL {int(hours)} HOUR GROUP BY event_source, region""", {"a": account})


def prioritize(account: str, framework: str, limit: int = 25) -> list[dict]:
    """Rank failing resources by evidence: severity + cost spike in the related service + activity signals."""
    anomalies = cost_anomalies(account)
    activity = suspicious_activity(account)
    prefixes = {}
    for a in anomalies:
        for pre in SERVICE_CHECKS.get(a["service"]) or (["bedrock", "iam"] if "Bedrock" in a["service"] else []):
            prefixes.setdefault(pre, []).append(f"cost spike {a['service']} {a['region']}: ${a['base']:.2f}->${a['today']:.2f}/day ({a['ratio']}x)")
    for s in activity:
        pre = s["service"].split(".")[0]
        prefixes.setdefault(pre, []).append(f"{s['signal']} x{s['n']} ({s['region']})")
    fails = db.query("""
    SELECT check_id, any(severity) AS severity, any(service) AS service, count() AS resources, groupArray(3)(resource_uid) AS sample
    FROM findings WHERE status='FAIL' AND account_id={a:String} AND scan_id IN
      (SELECT scan_id FROM scans WHERE account_id={a:String} AND framework={f:String} ORDER BY scan_time DESC LIMIT 1)
    GROUP BY check_id""", {"a": account, "f": framework})
    out = []
    for f in fails:
        ev = list(dict.fromkeys(prefixes.get(f["service"], [])))
        score = SEV_W.get(f["severity"], 1) + min(6, 2 * len(ev))
        verdict = "likely-being-used" if len(ev) >= 2 else "signal" if ev else "misconfigured-only"
        out.append({**f, "score": score, "evidence": ev, "verdict": verdict})
    return sorted(out, key=lambda x: -x["score"])[:limit]


DEMO_SPIKES = [  # (service, region, extra $ on the latest day, extra $ the day before, story)
    ("Amazon Elastic Compute Cloud - Compute", "us-east-1", 48.0, 6.0, "unexpected compute (cryptomining pattern)"),
    ("EC2 - Other", "us-east-1", 19.0, 1.0, "data transfer out (exfiltration pattern)"),
    ("Claude Sonnet 4.6 (Amazon Bedrock Edition)", "us-east-1", 22.0, 2.0, "model invocations (LLMjacking pattern)"),
]


def demo_spike(account: str, on: bool) -> dict:
    """Overlay clearly-labelled synthetic spend on top of the real Cost Explorer data. Never touches real rows."""
    c = db.init()
    c.command("ALTER TABLE cost_demo DELETE WHERE account_id = %(a)s SETTINGS mutations_sync=1", parameters={"a": account})
    if on:
        d = db.query("SELECT max(day) AS d FROM cost_daily WHERE account_id={a:String}", {"a": account})[0]["d"]
        rows = []
        for svc, region, today, yday, note in DEMO_SPIKES:
            rows += [[d, account, svc, region, today, "DEMO: " + note], [d - timedelta(days=1), account, svc, region, yday, "DEMO: " + note]]
        c.insert("cost_demo", rows, column_names=["day", "account_id", "service", "region", "amount", "note"])
    return {"demo_spike": on}


def demo_active(account: str) -> bool:
    return db.query("SELECT count() AS n FROM cost_demo WHERE account_id={a:String}", {"a": account})[0]["n"] > 0


def series(account: str, days: int = 14, top: int = 5) -> list[dict]:
    """Daily cost for the services with the highest latest-day spend (real + demo overlay)."""
    rows = db.query(f"""
    SELECT service, region, day, sum(amount) AS total, sumIf(amount, src = 1) AS demo_amt FROM (
      SELECT service, region, day, amount, 0 AS src FROM cost_daily WHERE account_id={{a:String}}
      UNION ALL SELECT service, region, day, amount, 1 AS src FROM cost_demo WHERE account_id={{a:String}})
    WHERE day > (SELECT max(day) FROM cost_daily WHERE account_id={{a:String}}) - {int(days)} AND region != 'global'
    GROUP BY service, region, day ORDER BY service, region, day""", {"a": account})
    by = {}
    for r in rows:
        by.setdefault((r["service"], r["region"]), []).append({"day": str(r["day"]), "amount": round(r["total"], 2), "demo": round(r["demo_amt"], 2)})
    out = [{"service": k[0], "region": k[1], "days": v, "latest": v[-1]["amount"], "base": round(sum(x["amount"] for x in v[:-2]) / max(1, len(v) - 2), 2)} for k, v in by.items()]
    return sorted(out, key=lambda x: -x["latest"])[:top]
