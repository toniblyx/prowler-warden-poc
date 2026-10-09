"""Load Prowler's compliance frameworks and check metadata straight from the Prowler OSS package."""
import json
from functools import lru_cache
from pathlib import Path

import prowler

ROOT = Path(prowler.__file__).parent
COMPLIANCE_DIR = ROOT / "compliance" / "aws"
SERVICES_DIR = ROOT / "providers" / "aws" / "services"


def list_frameworks() -> list[str]:
    return sorted(p.stem for p in COMPLIANCE_DIR.glob("*.json"))


@lru_cache
def load(framework: str) -> dict:
    return json.loads((COMPLIANCE_DIR / f"{framework}.json").read_text())


def rows(framework: str) -> list[list]:
    """framework_map rows: one per (requirement, check); manual requirements get an empty check."""
    fw = load(framework)
    out = []
    for r in fw["Requirements"]:
        attrs = (r.get("Attributes") or [{}])[0]
        section = attrs.get("Section") or attrs.get("Name") or attrs.get("Domain") or ""
        checks = r.get("Checks") or []
        if not checks:
            out.append([framework, str(r["Id"]), section, r.get("Description", ""), "", 1])
        for c in checks:
            out.append([framework, str(r["Id"]), section, r.get("Description", ""), c, 0])
    return out


@lru_cache
def check_metadata(check_id: str) -> dict:
    service = check_id.split("_")[0]
    p = SERVICES_DIR / service / check_id / f"{check_id}.metadata.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def has_fixer(check_id: str) -> bool:
    service = check_id.split("_")[0]
    return (SERVICES_DIR / service / check_id / f"{check_id}_fixer.py").exists()
