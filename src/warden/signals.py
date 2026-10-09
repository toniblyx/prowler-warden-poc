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
      FROM cost_daily WHERE account_id={{a:String}} GROUP BY service, region)
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
        for pre in SERVICE_CHECKS.get(a["service"], []):
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
        ev = prefixes.get(f["service"], []) + (prefixes.get("iam", []) if f["service"] == "iam" else [])
        score = SEV_W.get(f["severity"], 1) + min(6, 2 * len(ev))
        verdict = "likely-being-used" if len(ev) >= 2 else "signal" if ev else "misconfigured-only"
        out.append({**f, "score": score, "evidence": ev, "verdict": verdict})
    return sorted(out, key=lambda x: -x["score"])[:limit]
