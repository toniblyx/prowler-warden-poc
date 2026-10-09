import os
from pathlib import Path

for _l in (Path(__file__).resolve().parents[2] / ".env").read_text().splitlines() if (Path(__file__).resolve().parents[2] / ".env").exists() else []:
    if "=" in _l and not _l.startswith("#"):
        _k, _v = _l.split("=", 1)
        if _v.strip():
            os.environ.setdefault(_k.strip(), _v.strip())

CH_HOST = os.getenv("WARDEN_CH_HOST", "localhost")
CH_PORT = int(os.getenv("WARDEN_CH_PORT", "8123"))
CH_USER = os.getenv("WARDEN_CH_USER", "default")
CH_PASSWORD = os.getenv("WARDEN_CH_PASSWORD", "warden")
CH_DB = os.getenv("WARDEN_CH_DB", "warden")
MODEL = os.getenv("WARDEN_MODEL", "claude-sonnet-5-5")
DEFAULT_FRAMEWORK = os.getenv("WARDEN_FRAMEWORK", "cis_5.0_aws")

PROFILE = os.getenv("WARDEN_PROFILE") or None
ACCOUNT = os.getenv("WARDEN_ACCOUNT", "")
REGION = os.getenv("WARDEN_REGION", "us-east-1")
