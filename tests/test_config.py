import os
from email_intel.config import load_config, Config


def test_default_config():
    cfg = load_config(config_path="/nonexistent/config.toml")
    assert cfg.geo_provider == "ip-api"
    assert cfg.maxmind_db_path is None
    assert cfg.default_days == 30
    assert cfg.default_limit == 500
    assert cfg.default_format == "table"


def test_config_from_toml(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text("""
[geo]
provider = "maxmind"
maxmind_db_path = "/opt/GeoLite2-City.mmdb"

[defaults]
days = 7
limit = 100
format = "json"
""")
    cfg = load_config(config_path=str(config_file))
    assert cfg.geo_provider == "maxmind"
    assert cfg.maxmind_db_path == "/opt/GeoLite2-City.mmdb"
    assert cfg.default_days == 7
    assert cfg.default_limit == 100
    assert cfg.default_format == "json"


def test_config_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("MAXMIND_DB_PATH", "/env/path.mmdb")
    cfg = load_config(config_path="/nonexistent/config.toml")
    assert cfg.maxmind_db_path == "/env/path.mmdb"
