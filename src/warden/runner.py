"""Run Prowler OSS against AWS and ingest results into ClickHouse."""
import json
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import db, frameworks

COLS = ["scan_id", "scan_time", "account_id", "region", "check_id", "service", "severity", "status",
        "resource_uid", "resource_name", "status_extended", "risk", "remediation_desc", "remediation_cli"]


def run_prowler(framework: str, profile: str | None, regions: list[str] | None, checks: list[str] | None) -> Path:
    out = Path(tempfile.mkdtemp(prefix="warden-"))
    cmd = [str(Path(sys.executable).parent / "prowler"), "aws", "--compliance", framework,
           "-M", "json-ocsf", "-o", str(out), "-F", "scan", "--no-banner", "--ignore-exit-code-3"]
    if profile:
        cmd += ["--profile", profile]
    if regions:
        cmd += ["--region", *regions]
    if checks:
        cmd += ["--check", *checks]
    subprocess.run(cmd, check=True)
    return next(out.glob("*.ocsf.json"))


def run_prowler_checks(checks: list[str], profile: str | None, regions: list[str] | None) -> Path:
    out = Path(tempfile.mkdtemp(prefix="warden-verify-"))
    cmd = [str(Path(sys.executable).parent / "prowler"), "aws", "--check", *checks, "-M", "json-ocsf", "-o", str(out),
           "-F", "verify", "--no-banner", "--ignore-exit-code-3"]
    if profile:
        cmd += ["--profile", profile]
    if regions:
        cmd += ["--region", *regions]
    subprocess.run(cmd, check=True)
    return next(out.glob("*.ocsf.json"))


def ingest_findings_only(rows: list[list]):
    """Partial (event-triggered) scans: store the evidence but not as a full scan, so score/drift stay comparable."""
    if rows:
        db.init().insert("findings", rows, column_names=COLS)


def parse_ocsf(path: Path, scan_id: str) -> list[list]:
    rows = []
    for f in json.loads(path.read_text()):
        if f.get("status_code") not in ("PASS", "FAIL"):
            continue
        res = (f.get("resources") or [{}])[0]
        meta = f.get("metadata", {})
        check = meta.get("event_code") or f["finding_info"]["uid"]
        rem = f.get("remediation", {})
        refs = rem.get("references") or []
        cli = next((r for r in refs if r.startswith(("aws ", "terraform", "resource "))), "")
        rows.append([
            scan_id, datetime.fromtimestamp(f["time"], timezone.utc).replace(tzinfo=None),
            f["cloud"]["account"]["uid"], f["cloud"].get("region") or res.get("region", ""),
            check, check.split("_")[0], (f.get("severity") or "").lower(), f["status_code"],
            res.get("uid", ""), res.get("name", ""), f.get("status_detail", ""),
            f.get("risk_details", ""), rem.get("desc", ""), cli,
        ])
    return rows


def ingest(rows: list[list], framework: str, source: str):
    c = db.init()
    if not rows:
        return None
    scan_id, ts, account = rows[0][0], rows[0][1], rows[0][2]
    c.insert("findings", rows, column_names=COLS)
    c.insert("scans", [[scan_id, ts, account, framework, source, len(rows)]],
             column_names=["scan_id", "scan_time", "account_id", "framework", "source", "findings"])
    return scan_id


def load_framework(framework: str):
    c = db.init()
    c.command("ALTER TABLE framework_map DELETE WHERE framework = %(f)s SETTINGS mutations_sync=1", parameters={"f": framework})
    c.insert("framework_map", frameworks.rows(framework),
             column_names=["framework", "req_id", "section", "description", "check_id", "manual"])


def scan(framework: str, profile: str | None = None, regions: list[str] | None = None, checks: list[str] | None = None) -> str:
    load_framework(framework)
    path = run_prowler(framework, profile, regions, checks)
    sid = uuid.uuid4().hex[:12]
    return ingest(parse_ocsf(path, sid), framework, "prowler-live")
