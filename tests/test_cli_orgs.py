from unittest.mock import patch
from click.testing import CliRunner
from email_intel.cli import main
from email_intel.config import Config

_DEFAULT_DIR_STR = str(__import__('pathlib').Path.home() / ".email-intel")

def _test_config(tmp_path):
    return Config(
        orgs_db_path=str(tmp_path / "orgs.db"),
        cache_db_path=str(tmp_path / "geo_cache.db"),
        plocamium_enabled=False,
        plocamium_local_path=str(tmp_path / "signals.jsonl"),
    )

def test_orgs_list_empty(tmp_path):
    runner = CliRunner()
    with patch("email_intel.cli.load_config", return_value=_test_config(tmp_path)):
        result = runner.invoke(main, ["orgs"])
    assert result.exit_code == 0
    assert "No org profiles" in result.output

def test_orgs_map_and_show(tmp_path):
    runner = CliRunner()
    cfg = _test_config(tmp_path)
    with patch("email_intel.cli.load_config", return_value=cfg):
        result = runner.invoke(main, ["orgs", "map", "gs.com", "Goldman Sachs", "--sector", "Financial Services"])
        assert result.exit_code == 0
        result = runner.invoke(main, ["orgs", "show", "gs.com"])
        assert result.exit_code == 0
        assert "gs.com" in result.output

def test_changes_empty(tmp_path):
    runner = CliRunner()
    with patch("email_intel.cli.load_config", return_value=_test_config(tmp_path)):
        result = runner.invoke(main, ["changes"])
    assert result.exit_code == 0
    assert "No changes" in result.output

def test_scan_with_profile(gmail_headers):
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", "--format", "json"], input=gmail_headers)
    assert result.exit_code == 0
