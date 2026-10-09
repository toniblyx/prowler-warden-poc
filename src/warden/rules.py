"""CloudTrail detections: each rule maps an API event to the Prowler checks (and so the compliance requirements) it can break."""
import json
from dataclasses import dataclass, field


@dataclass
class Hit:
    rule_id: str
    title: str
    severity: str
    checks: list[str]
    resource: str = ""


def _items(x):
    return (x or {}).get("items", []) if isinstance(x, dict) else (x or [])


def _open_ports(p: dict):
    """Ports opened to the whole internet by an AuthorizeSecurityGroupIngress call (None = all ports)."""
    out = []
    for perm in _items((p or {}).get("ipPermissions")):
        cidrs = [r.get("cidrIp") for r in _items(perm.get("ipRanges"))] + [r.get("cidrIpv6") for r in _items(perm.get("ipv6Ranges"))]
        if any(c in ("0.0.0.0/0", "::/0") for c in cidrs):
            lo, hi, proto = perm.get("fromPort"), perm.get("toPort"), perm.get("ipProtocol")
            out.append(None if proto in ("-1", -1) else (lo, hi))
    return out


def evaluate(e: dict) -> list[Hit]:
    """e is a normalized event row (dict) with request_params already parsed under 'params'."""
    n, p, hits = e["event_name"], e.get("params") or {}, []
    if e.get("error_code"):
        return hits  # failed calls changed nothing
    add = lambda *a, **k: hits.append(Hit(*a, **k))

    if n == "AuthorizeSecurityGroupIngress":
        for rng in _open_ports(p):
            sg = p.get("groupId", "")
            if rng is None:
                add("sg_open_all", "Security group opened to the internet on all ports", "critical", ["ec2_securitygroup_allow_ingress_from_internet_to_any_port"], sg)
            else:
                lo, hi = rng
                for port, chk in ((22, "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"), (3389, "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389")):
                    if lo is not None and lo <= port <= hi:
                        add(f"sg_open_{port}", f"Port {port} opened to the internet", "high", [chk], sg)
    elif n in ("PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock"):
        cfg = p.get("PublicAccessBlockConfiguration") or {}
        if n == "DeleteBucketPublicAccessBlock" or not all(cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
            add("s3_pab_weakened", "S3 bucket public access block removed or weakened", "high", ["s3_bucket_level_public_access_block"], p.get("bucketName", ""))
    elif n in ("PutAccountPublicAccessBlock", "DeletePublicAccessBlock"):
        add("s3_account_pab_weakened", "S3 account-level public access block changed", "high", ["s3_account_level_public_access_blocks"])
    elif n == "PutBucketPolicy":
        add("s3_policy_changed", "S3 bucket policy changed", "medium", ["s3_bucket_policy_public_write_access"], p.get("bucketName", ""))
    elif n in ("StopLogging", "DeleteTrail"):
        add("trail_disabled", "CloudTrail logging stopped or trail deleted", "critical", ["cloudtrail_multi_region_enabled"], p.get("name", ""))
    elif n == "UpdateTrail":
        add("trail_updated", "CloudTrail trail configuration changed", "medium", ["cloudtrail_multi_region_enabled", "cloudtrail_log_file_validation_enabled"], p.get("name", ""))
    elif n in ("StopConfigurationRecorder", "DeleteConfigurationRecorder"):
        add("config_disabled", "AWS Config recorder stopped or deleted", "high", ["config_recorder_all_regions_enabled"])
    elif n == "DeleteFlowLogs":
        add("flowlogs_deleted", "VPC flow logs deleted", "medium", ["vpc_flow_logs_enabled"])
    elif n in ("ScheduleKeyDeletion", "DisableKey"):
        add("kms_key_disabled", "KMS key disabled or scheduled for deletion", "high", ["kms_cmk_not_deleted_unintentionally"], p.get("keyId", ""))
    elif n == "DisableEbsEncryptionByDefault":
        add("ebs_default_enc_off", "EBS default encryption disabled", "high", ["ec2_ebs_default_encryption"])
    elif n == "CreateVolume" and str(p.get("encrypted", "false")).lower() != "true":
        add("ebs_unencrypted", "Unencrypted EBS volume created", "medium", ["ec2_ebs_volume_encryption"])
    elif n == "RunInstances" and (p.get("metadataOptions") or {}).get("httpTokens") != "required":
        add("imds_v1", "EC2 instance launched without IMDSv2 required", "medium", ["ec2_instance_imdsv2_enabled"])
    elif n in ("CreateDBInstance", "ModifyDBInstance") and p.get("publiclyAccessible") is True:
        add("rds_public", "RDS instance made publicly accessible", "critical", ["rds_instance_no_public_access"], p.get("dBInstanceIdentifier", ""))
    elif n in ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy") and str(p.get("policyArn", "")).endswith("/AdministratorAccess"):
        add("admin_attached", "AdministratorAccess attached", "high", ["iam_aws_attached_policy_no_administrative_privileges"], p.get("userName") or p.get("roleName") or p.get("groupName", ""))
    elif n == "CreateAccessKey" and e.get("user_type") == "Root":
        add("root_key_created", "Access key created for the root user", "critical", ["iam_no_root_access_key"])
    elif n == "ConsoleLogin" and e.get("mfa_used") == "No" and e.get("user_type") != "Root":
        add("login_no_mfa", "Console login without MFA", "medium", ["iam_user_mfa_enabled_console_access"], e.get("user_arn", ""))

    if e.get("user_type") == "Root" and n != "ConsoleLogin" or (n == "ConsoleLogin" and e.get("user_type") == "Root"):
        add("root_usage", "Root account used", "critical", ["iam_avoid_root_usage"], e.get("user_arn", ""))
    return hits
