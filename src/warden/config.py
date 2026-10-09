import os

CH_HOST = os.getenv("WARDEN_CH_HOST", "localhost")
CH_PORT = int(os.getenv("WARDEN_CH_PORT", "8123"))
CH_USER = os.getenv("WARDEN_CH_USER", "default")
CH_PASSWORD = os.getenv("WARDEN_CH_PASSWORD", "warden")
CH_DB = os.getenv("WARDEN_CH_DB", "warden")
MODEL = os.getenv("WARDEN_MODEL", "claude-sonnet-5-5")
DEFAULT_FRAMEWORK = os.getenv("WARDEN_FRAMEWORK", "cis_5.0_aws")
