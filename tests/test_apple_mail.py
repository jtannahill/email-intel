import os
from pathlib import Path
from datetime import datetime, timezone
from email_intel.apple_mail import parse_emlx, find_emlx_files


def _create_emlx(path: Path, headers: str) -> Path:
    body = headers + "\nBody text here.\n"
    byte_count = len(body.encode("utf-8"))
    content = f"{byte_count}\n{body}"
    content += """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict/>
</plist>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_parse_emlx_valid(tmp_path):
    emlx = _create_emlx(
        tmp_path / "1.emlx",
        "From: test@example.com\nTo: me@test.com\nSubject: Hello\nDate: Wed, 19 Mar 2026 10:00:00 +0000\n",
    )
    headers = parse_emlx(str(emlx))
    assert headers is not None
    assert "From: test@example.com" in headers


def test_parse_emlx_corrupt(tmp_path):
    bad_file = tmp_path / "bad.emlx"
    bad_file.write_text("not a valid emlx file")
    headers = parse_emlx(str(bad_file))
    assert headers is None


def test_find_emlx_files(tmp_path):
    mail_dir = tmp_path / "Library" / "Mail" / "V10" / "account" / "INBOX.mbox"
    _create_emlx(mail_dir / "1.emlx", "From: a@test.com\nDate: Wed, 19 Mar 2026 10:00:00 +0000\n")
    _create_emlx(mail_dir / "2.emlx", "From: b@test.com\nDate: Wed, 18 Mar 2026 10:00:00 +0000\n")

    files = find_emlx_files(base_dir=str(tmp_path / "Library" / "Mail"))
    assert len(files) == 2


def test_find_emlx_files_empty(tmp_path):
    files = find_emlx_files(base_dir=str(tmp_path / "nonexistent"))
    assert files == []
