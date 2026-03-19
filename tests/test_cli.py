from click.testing import CliRunner
from email_intel.cli import main


def test_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_analyze_stdin(gmail_headers):
    runner = CliRunner()
    result = runner.invoke(main, ["analyze"], input=gmail_headers)
    assert result.exit_code == 0
    assert "sender@example.com" in result.output


def test_analyze_file(tmp_path, gmail_headers):
    f = tmp_path / "test.txt"
    f.write_text(gmail_headers)
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", "--file", str(f)])
    assert result.exit_code == 0
    assert "sender@example.com" in result.output


def test_analyze_json_format(gmail_headers):
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", "--format", "json"], input=gmail_headers)
    assert result.exit_code == 0
    import json
    data = json.loads(result.output)
    assert data[0]["from_addr"] == "sender@example.com"
