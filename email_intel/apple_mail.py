from __future__ import annotations
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_MAIL_DIR = Path.home() / "Library" / "Mail"


def parse_emlx(file_path: str) -> str | None:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline().strip()
            try:
                byte_count = int(first_line)
            except ValueError:
                logger.warning("Invalid .emlx byte count in %s: %s", file_path, first_line)
                return None

            message_bytes = f.read(byte_count)
            if not message_bytes:
                return None

            header_end = message_bytes.find("\n\n")
            if header_end > 0:
                return message_bytes[:header_end]
            return message_bytes

    except (OSError, IOError) as e:
        logger.warning("Failed to read .emlx file %s: %s", file_path, e)
        return None


def find_emlx_files(
    base_dir: str | None = None,
    days: int | None = None,
    from_filter: str | None = None,
    query: str | None = None,
) -> list[str]:
    mail_dir = Path(base_dir) if base_dir else _DEFAULT_MAIL_DIR
    if not mail_dir.exists():
        return []

    cutoff = None
    if days:
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)

    results: list[str] = []

    for emlx_path in mail_dir.rglob("*.emlx"):
        if not emlx_path.is_file():
            continue

        if cutoff:
            mtime = datetime.fromtimestamp(emlx_path.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                continue

        if from_filter or query:
            headers = parse_emlx(str(emlx_path))
            if headers is None:
                continue

            if from_filter:
                from_line = ""
                for line in headers.split("\n"):
                    if line.lower().startswith("from:"):
                        from_line = line
                        break
                if from_filter.lower() not in from_line.lower():
                    continue
            if query and query.lower() not in headers.lower():
                continue

        results.append(str(emlx_path))

    return sorted(results)
