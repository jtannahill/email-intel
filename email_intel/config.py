from __future__ import annotations
import os
import sys
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

_DEFAULT_DIR = Path.home() / ".email-intel"


@dataclass
class Config:
    geo_provider: str = "ip-api"
    maxmind_db_path: str | None = None
    gmail_credentials_path: str = str(_DEFAULT_DIR / "credentials.json")
    gmail_token_path: str = str(_DEFAULT_DIR / "gmail_token.json")
    default_days: int = 30
    default_limit: int = 500
    default_format: str = "table"
    cache_db_path: str = str(_DEFAULT_DIR / "geo_cache.db")
    # Org profiling
    orgs_enabled: bool = True
    orgs_db_path: str = str(_DEFAULT_DIR / "orgs.db")
    # Plocamium bridge
    plocamium_enabled: bool = False
    plocamium_output: str = "local"
    plocamium_local_path: str = str(_DEFAULT_DIR / "signals.jsonl")
    plocamium_s3_bucket: str = ""
    plocamium_s3_prefix: str = "email-intel/"
    plocamium_s3_profile: str = ""


def load_config(config_path: str | None = None) -> Config:
    path = config_path or str(_DEFAULT_DIR / "config.toml")
    cfg = Config()

    if Path(path).exists() and tomllib:
        with open(path, "rb") as f:
            data = tomllib.load(f)

        geo = data.get("geo", {})
        cfg.geo_provider = geo.get("provider", cfg.geo_provider)
        cfg.maxmind_db_path = geo.get("maxmind_db_path") or cfg.maxmind_db_path

        gmail = data.get("gmail", {})
        cfg.gmail_credentials_path = gmail.get("credentials_path") or cfg.gmail_credentials_path

        defaults = data.get("defaults", {})
        cfg.default_days = defaults.get("days", cfg.default_days)
        cfg.default_limit = defaults.get("limit", cfg.default_limit)
        cfg.default_format = defaults.get("format", cfg.default_format)

        orgs = data.get("orgs", {})
        if "enabled" in orgs:
            cfg.orgs_enabled = orgs["enabled"]
        cfg.orgs_db_path = orgs.get("db_path") or cfg.orgs_db_path

        ploc = data.get("plocamium", {})
        if "enabled" in ploc:
            cfg.plocamium_enabled = ploc["enabled"]
        cfg.plocamium_output = ploc.get("output", cfg.plocamium_output)
        cfg.plocamium_local_path = ploc.get("local_path") or cfg.plocamium_local_path
        cfg.plocamium_s3_bucket = ploc.get("s3_bucket") or cfg.plocamium_s3_bucket
        cfg.plocamium_s3_prefix = ploc.get("s3_prefix", cfg.plocamium_s3_prefix)
        cfg.plocamium_s3_profile = ploc.get("s3_profile") or cfg.plocamium_s3_profile

    if os.environ.get("MAXMIND_DB_PATH"):
        cfg.maxmind_db_path = os.environ["MAXMIND_DB_PATH"]
    if os.environ.get("GMAIL_CREDENTIALS_PATH"):
        cfg.gmail_credentials_path = os.environ["GMAIL_CREDENTIALS_PATH"]

    return cfg
