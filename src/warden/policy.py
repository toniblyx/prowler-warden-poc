"""Runtime-configurable remediation policy, stored in ClickHouse so it can change without a restart."""
import json
import os

from . import db

DEFAULTS = {
    "mode": "pr",               # monitor | pr (human reviews a PR) | auto (agent fixes AWS directly)
    "dry_run": "true",          # in auto mode: log what would be changed instead of changing it
    "auto_min_severity": "low", # only auto-fix findings at/above this severity
    "auto_deny_checks": "[]",   # JSON list: never auto-fix these checks (fall back to PR)
    "auto_allow_regions": "[]", # JSON list; empty = all regions
    "repo": "",                 # local path of the IaC repo used in pr mode
    "open_pr": "false",         # pr mode: actually push + open the PR (otherwise prepare a local branch)
}
MODES = ("monitor", "pr", "auto")
SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def get() -> dict:
    db.init()
    cur = dict(DEFAULTS)
    for r in db.query("SELECT key, argMax(value, updated) AS value FROM policy GROUP BY key"):
        cur[r["key"]] = r["value"]
    return {"mode": cur["mode"], "dry_run": cur["dry_run"] == "true", "auto_min_severity": cur["auto_min_severity"],
            "auto_deny_checks": json.loads(cur["auto_deny_checks"]), "auto_allow_regions": json.loads(cur["auto_allow_regions"]),
            "repo": cur["repo"] or os.getenv("WARDEN_REPO", ""), "open_pr": cur["open_pr"] == "true"}


def set_(key: str, value) -> dict:
    if key not in DEFAULTS:
        raise ValueError(f"unknown setting {key}")
    if key == "mode" and value not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    if isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, (list, dict)):
        value = json.dumps(value)
    db.init().insert("policy", [[key, str(value)]], column_names=["key", "value"])
    return get()
