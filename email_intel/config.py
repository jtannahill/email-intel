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

    if os.environ.get("MAXMIND_DB_PATH"):
        cfg.maxmind_db_path = os.environ["MAXMIND_DB_PATH"]
    if os.environ.get("GMAIL_CREDENTIALS_PATH"):
        cfg.gmail_credentials_path = os.environ["GMAIL_CREDENTIALS_PATH"]

    return cfg
