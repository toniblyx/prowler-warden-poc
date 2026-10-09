"""Remediation router. Mode comes from the runtime policy:
  monitor -> alert only; pr -> human reviews a pull request; auto -> fix AWS directly, then re-verify with Prowler.
Auto-fixes are narrow, idempotent boto3 calls. Anything without a safe auto-fix falls back to a PR, never a guess."""
import json
import re

import boto3

from pathlib import Path

from . import db, frameworks, iac, policy


def _sess(profile, region):
    return boto3.Session(profile_name=profile, region_name=region)


def _sg_close_internet(profile, region, resource, check):
    port = 22 if check.endswith("port_22") else 3389 if check.endswith("port_3389") else None
    sg_id = resource.split("/")[-1]
    ec2 = _sess(profile, region).client("ec2")
    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    revoked = []
    for perm in sg["IpPermissions"]:
        lo, hi = perm.get("FromPort"), perm.get("ToPort")
        if port is not None and not (lo is not None and lo <= port <= hi):
            continue
        bad4 = [r for r in perm.get("IpRanges", []) if r["CidrIp"] == "0.0.0.0/0"]
        bad6 = [r for r in perm.get("Ipv6Ranges", []) if r["CidrIpv6"] == "::/0"]
        if bad4 or bad6:
            req = {"IpProtocol": perm["IpProtocol"], "IpRanges": bad4, "Ipv6Ranges": bad6}
            if "FromPort" in perm:
                req.update(FromPort=lo, ToPort=hi)
            revoked.append(req)
    if revoked:
        ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=revoked)
    return {"undo": {"authorize_security_group_ingress": {"GroupId": sg_id, "IpPermissions": revoked}}}


def _bucket_pab(profile, region, resource, check):
    bucket = resource.split(":::")[-1].split("/")[0]
    _sess(profile, region).client("s3").put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    return {"undo": None}


def _account_pab(profile, region, resource, check):
    acct = _sess(profile, region).client("sts").get_caller_identity()["Account"]
    _sess(profile, region).client("s3control").put_public_access_block(AccountId=acct, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    return {"undo": None}


def _trail_start(profile, region, resource, check):
    ct = _sess(profile, region).client("cloudtrail")
    for t in ct.describe_trails()["trailList"]:
        ct.start_logging(Name=t["TrailARN"])
    return {"undo": None}


def _ebs_default_enc(profile, region, resource, check):
    _sess(profile, region).client("ec2").enable_ebs_encryption_by_default()
    return {"undo": None}


def _rds_private(profile, region, resource, check):
    ident = resource.split(":")[-1]
    _sess(profile, region).client("rds").modify_db_instance(DBInstanceIdentifier=ident, PubliclyAccessible=False, ApplyImmediately=True)
    return {"undo": {"modify_db_instance": {"DBInstanceIdentifier": ident, "PubliclyAccessible": True}}}


REMEDIATORS = {
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": _sg_close_internet,
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389": _sg_close_internet,
    "ec2_securitygroup_allow_ingress_from_internet_to_any_port": _sg_close_internet,
    "s3_bucket_level_public_access_block": _bucket_pab,
    "s3_account_level_public_access_blocks": _account_pab,
    "cloudtrail_multi_region_enabled": _trail_start,
    "ec2_ebs_default_encryption": _ebs_default_enc,
    "rds_instance_no_public_access": _rds_private,
}


def _record(account, framework, kind, check, resource, summary, command, status):
    db.client().insert("actions", [[account, framework, kind, check, resource, summary, command, status]],
                       column_names=["account_id", "framework", "kind", "check_id", "resource_uid", "summary", "command", "status"])
    _notify(account, framework, kind, check, resource, summary, command, status)


_NOTIFY_STATUS = {"fixed-verified", "fix-applied-still-failing", "failed", "pr-opened", "pr-ready", "dry-run"}


def _notify(account, framework, kind, check, resource, summary, command, status):
    """Best-effort Slack alert via Guild.ai; never affects remediation."""
    try:
        if kind not in ("self-fix", "pr") or status not in _NOTIFY_STATUS:
            return
        from . import notify
        pol = policy.get()
        pr_url = command if kind == "pr" and str(command).startswith("http") else None
        notify.send_action({"action_kind": kind, "severity": frameworks.check_metadata(check).get("Severity", ""), "check_id": check, "resource": resource,
                            "account": account, "summary": summary, "status": status, "pr_url": pr_url,
                            "mode": pol.get("mode", ""), "framework": framework})
    except Exception:
        pass


def _code_track(pol, account, framework, chk, res, region, profile, note):
    """Open (or prepare) a PR against the Terraform that owns the resource, so code and cloud stay in sync."""
    if not pol["repo"]:
        return None
    try:
        r = iac.fix_in_code(Path(pol["repo"]), res, chk, region, profile, note, open_pr=pol["open_pr"])
    except Exception as e:
        r = {"status": "error", "note": str(e)[:200]}
    _record(account, framework, "pr", chk, res, f"code: {r.get('status')} {r.get('address', '')} {r.get('note', '')}".strip(), r.get("pr") or r.get("branch") or "",
            {"pr-opened": "pr-opened", "branch-ready": "pr-ready"}.get(r.get("status"), r.get("status", "")))
    return r


def handle(v: dict, framework: str, profile: str | None) -> dict:
    """v = verified violation from cloudtrail.verify(). Applies the current policy and records evidence."""
    pol = policy.get()
    det = v["detection"]
    account = det["account_id"]
    out = {"detection": v["id"], "mode": pol["mode"], "results": []}
    for f in v["failing"]:
        chk, res, region = f["check_id"], f["resource_uid"], f["region"] or det["region"]
        sev = det["severity"]
        if det.get("resource") and det["resource"] not in res:
            continue  # defence in depth: act only on the resource named in the triggering event
        if pol["mode"] == "monitor":
            out["results"].append({"check": chk, "resource": res, "action": "alert-only"})
            continue
        auto_ok = (pol["mode"] == "auto" and chk in REMEDIATORS and chk not in pol["auto_deny_checks"]
                   and policy.SEV.get(sev, 0) >= policy.SEV[pol["auto_min_severity"]]
                   and (not pol["auto_allow_regions"] or region in pol["auto_allow_regions"]))
        if auto_ok:
            if pol["dry_run"]:
                _record(account, framework, "self-fix", chk, res, f"[dry-run] would fix {chk}", REMEDIATORS[chk].__name__, "dry-run")
                out["results"].append({"check": chk, "resource": res, "action": "would-auto-fix (dry-run)"})
                continue
            try:
                undo = REMEDIATORS[chk](profile, region, res, chk)
                from . import runner  # re-verify with Prowler: the fix only counts if the check now passes
                rows = runner.parse_ocsf(runner.run_prowler_checks([chk], profile, [region]), f"verify-fix-{v['id']}")
                runner.ingest_findings_only(rows)
                still = [r for r in rows if r[7] == "FAIL" and (res in r[8] or res in r[9])]
                status = "fixed-verified" if not still else "fix-applied-still-failing"
                _record(account, framework, "self-fix", chk, res, f"auto-fixed {chk}", json.dumps(undo), status)
                out["results"].append({"check": chk, "resource": res, "action": status, "code": _code_track(pol, account, framework, chk, res, region, profile, f"Runtime fix applied by Warden ({status}).")})
            except Exception as e:
                _record(account, framework, "self-fix", chk, res, f"auto-fix failed: {e}", "", "failed")
                out["results"].append({"check": chk, "resource": res, "action": f"failed: {e}"})
            continue
        # pr mode, or auto mode without a safe auto-fix: a human reviews
        _record(account, framework, "pr", chk, res, f"{sev} {chk} needs review" + (" (no safe auto-fix)" if pol["mode"] == "auto" else ""),
                "", "pr-queued")
        out["results"].append({"check": chk, "resource": res, "action": "pr-queued",
                               "code": _code_track(pol, account, framework, chk, res, region, profile, "Detected by Warden; no runtime change was made (human review).")})
    return out


def revert(action_id: str, profile: str | None, region: str) -> dict:
    """Undo a self-fix using the inverse call recorded when it was applied."""
    rows = db.query("SELECT * FROM actions FINAL WHERE toString(id) = {i:String}", {"i": action_id})
    if not rows or rows[0]["kind"] != "self-fix":
        return {"error": "not a self-fix action"}
    a = rows[0]
    undo = (json.loads(a["command"] or "null") or {}).get("undo")
    if not undo:
        return {"error": "nothing to undo for this fix"}
    sess = _sess(profile, region)
    if "authorize_security_group_ingress" in undo:
        u = undo["authorize_security_group_ingress"]
        sess.client("ec2").authorize_security_group_ingress(GroupId=u["GroupId"], IpPermissions=u["IpPermissions"])
    elif "modify_db_instance" in undo:
        sess.client("rds").modify_db_instance(ApplyImmediately=True, **undo["modify_db_instance"])
    db.client().insert("actions", [[a["account_id"], a["framework"], "self-fix", a["check_id"], a["resource_uid"], a["summary"] + " (reverted)", a["command"], "reverted"]],
                       column_names=["account_id", "framework", "kind", "check_id", "resource_uid", "summary", "command", "status"])
    return {"reverted": action_id}
