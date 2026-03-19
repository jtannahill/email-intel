# Email Intel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI that analyzes email headers for sender geolocation, client fingerprinting, auth validation, and communication patterns across Gmail and Apple Mail.

**Architecture:** Modular Python package with Click CLI. Parser extracts structured data from RFC 822 headers, geo module resolves IPs to locations with SQLite caching, source modules (Gmail OAuth2, Apple Mail .emlx, stdin) provide headers, reporter formats output as rich tables or JSON/CSV exports.

**Tech Stack:** Python 3.11+, Click, Rich, requests, google-auth-oauthlib, google-api-python-client, geoip2 (optional), tomli, sqlite3 (stdlib)

**Spec:** `docs/superpowers/specs/2026-03-19-email-intel-design.md`

---

## File Structure

```
email-intel/
├── email_intel/
│   ├── __init__.py         # version string
│   ├── models.py           # dataclasses: ServerHop, AuthResult, GeoResult, EmailAnalysis, ScanSummary
│   ├── parser.py           # RFC 822 header parsing, IP extraction, client fingerprinting
│   ├── geo.py              # GeoProvider protocol, IpApiProvider, MaxMindProvider, GeoCache
│   ├── gmail_client.py     # Gmail OAuth2 auth + header fetching
│   ├── apple_mail.py       # .emlx file discovery + parsing
│   ├── config.py           # Config loading (~/.email-intel/config.toml + env vars)
│   ├── reporter.py         # Rich terminal output, JSON/CSV export
│   └── cli.py              # Click group: analyze, scan, auth subcommands
├── tests/
│   ├── conftest.py         # shared fixtures (sample headers, tmp dirs)
│   ├── test_models.py
│   ├── test_parser.py
│   ├── test_geo.py
│   ├── test_apple_mail.py
│   ├── test_reporter.py
│   ├── test_config.py
│   └── test_cli.py
├── pyproject.toml          # project metadata, dependencies, [project.scripts] entry point
└── docs/
    └── superpowers/
        ├── specs/...
        └── plans/...
```

---

### Task 1: Project Scaffolding + Models

**Files:**
- Create: `pyproject.toml`
- Create: `email_intel/__init__.py`
- Create: `email_intel/models.py`
- Create: `tests/conftest.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write pyproject.toml**

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"

[project]
name = "email-intel"
version = "0.1.0"
description = "Personal inbox intelligence — email header analysis CLI"
requires-python = ">=3.11"
dependencies = [
    "click>=8.1",
    "rich>=13.0",
    "requests>=2.31",
    "tomli>=2.0; python_version < '3.12'",
]

[project.optional-dependencies]
gmail = [
    "google-auth-oauthlib>=1.0",
    "google-api-python-client>=2.100",
]
maxmind = ["geoip2>=4.8"]
dev = ["pytest>=8.0", "pytest-cov>=4.1"]

[project.scripts]
email-intel = "email_intel.cli:main"
```

- [ ] **Step 2: Write `email_intel/__init__.py`**

```python
__version__ = "0.1.0"
```

- [ ] **Step 3: Write failing test for models**

```python
# tests/test_models.py
from datetime import datetime, timezone
from email_intel.models import ServerHop, AuthResult, GeoResult, EmailAnalysis, ScanSummary


def test_server_hop_creation():
    hop = ServerHop(
        server="mail-yw1.google.com",
        ip="74.125.82.42",
        timestamp=datetime(2026, 3, 19, 14, 30, 0, tzinfo=timezone.utc),
        protocol="ESMTPS",
        latency_ms=None,
    )
    assert hop.server == "mail-yw1.google.com"
    assert hop.ip == "74.125.82.42"


def test_auth_result_creation():
    auth = AuthResult(spf="pass", dkim="pass", dmarc="pass")
    assert auth.spf == "pass"


def test_geo_result_creation():
    geo = GeoResult(
        ip="74.125.82.42", city="Mountain View", region="California",
        country="US", lat=37.386, lon=-122.084, isp="Google LLC",
        org="Google LLC", source="ip-api",
    )
    assert geo.city == "Mountain View"


def test_email_analysis_creation():
    auth = AuthResult(spf="pass", dkim="pass", dmarc="pass")
    analysis = EmailAnalysis(
        message_id="<abc@mail.gmail.com>",
        from_addr="sender@gmail.com",
        to_addr="me@example.com",
        subject="Test",
        date=datetime(2026, 3, 19, 14, 30, 0, tzinfo=timezone.utc),
        timezone_offset="-0500",
        timezone_name="EST",
        mail_client="Gmail",
        hops=[],
        originating_ip=None,
        geo=None,
        auth=auth,
        reply_to_mismatch=False,
        is_bulk=False,
        flags=[],
    )
    assert analysis.from_addr == "sender@gmail.com"
    assert analysis.reply_to_mismatch is False


def test_scan_summary_creation():
    now = datetime(2026, 3, 19, tzinfo=timezone.utc)
    summary = ScanSummary(
        total_messages=0,
        date_range=(now, now),
        top_locations=[],
        timezone_distribution={},
        client_breakdown={},
        flagged_messages=[],
        emails=[],
    )
    assert summary.total_messages == 0
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cd /Users/jamest/email-intel && pip install -e ".[dev]" && pytest tests/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'email_intel.models'`

- [ ] **Step 5: Write `email_intel/models.py`**

```python
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ServerHop:
    server: str
    ip: str | None
    timestamp: datetime | None
    protocol: str | None
    latency_ms: float | None


@dataclass
class AuthResult:
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None


@dataclass
class GeoResult:
    ip: str
    city: str | None
    region: str | None
    country: str | None
    lat: float | None
    lon: float | None
    isp: str | None
    org: str | None
    source: str


@dataclass
class EmailAnalysis:
    message_id: str | None
    from_addr: str | None
    to_addr: str | None
    subject: str | None
    date: datetime | None
    timezone_offset: str | None
    timezone_name: str | None
    mail_client: str | None
    hops: list[ServerHop] = field(default_factory=list)
    originating_ip: str | None = None
    geo: GeoResult | None = None
    auth: AuthResult = field(default_factory=AuthResult)
    reply_to_mismatch: bool = False
    is_bulk: bool = False
    flags: list[str] = field(default_factory=list)


@dataclass
class ScanSummary:
    total_messages: int
    date_range: tuple[datetime, datetime]
    top_locations: list[tuple[str, int]] = field(default_factory=list)
    timezone_distribution: dict[str, int] = field(default_factory=dict)
    client_breakdown: dict[str, int] = field(default_factory=dict)
    flagged_messages: list[EmailAnalysis] = field(default_factory=list)
    emails: list[EmailAnalysis] = field(default_factory=list)
```

- [ ] **Step 6: Run tests and verify pass**

Run: `pytest tests/test_models.py -v`
Expected: All 5 tests PASS

- [ ] **Step 7: Write conftest.py with shared fixtures**

```python
# tests/conftest.py
import pytest

SAMPLE_HEADERS_GMAIL = """\
Delivered-To: me@gmail.com
Received: by 2002:a05:6902:1024:0:0:0:0 with SMTP id x4csp123456rwn;
        Wed, 19 Mar 2026 11:30:00 -0700 (PDT)
Received: from mail-yw1-f182.google.com (mail-yw1-f182.google.com. [209.85.128.182])
        by mx.google.com with ESMTPS id a1234b5678
        for <me@gmail.com>;
        Wed, 19 Mar 2026 11:29:59 -0700 (PDT)
Received: from [10.0.0.1] (c-74-125-82-42.hsd1.ny.comcast.net. [74.125.82.42])
        by smtp.gmail.com with ESMTPSA id d9876e5432
        for <me@gmail.com>;
        Wed, 19 Mar 2026 11:29:58 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of sender@example.com) smtp.mailfrom=sender@example.com;
       dkim=pass header.d=example.com;
       dmarc=pass (p=REJECT)
From: Sender Name <sender@example.com>
To: me@gmail.com
Subject: Test Email for Analysis
Date: Wed, 19 Mar 2026 14:29:58 -0500
Message-ID: <abc123@mail.gmail.com>
X-Mailer: Apple Mail (2.3654.60.5)
Reply-To: sender@example.com
Content-Type: text/plain; charset="UTF-8"
"""

SAMPLE_HEADERS_OUTLOOK = """\
Received: from BN6PR01MB2345.prod.exchangelabs.com (2603:10b6:404:6a::15)
 by BN6PR01MB6789.prod.exchangelabs.com with HTTPS; Wed, 19 Mar 2026 19:30:00 +0000
Received: from BN3NAM04FT005.eop-nam04.prod.protection.outlook.com
 (2603:10b6:404:6a:cafe::2) by BN6PR01MB2345.prod.exchangelabs.com
 (2603:10b6:404:6a::15) with Microsoft SMTP Server; Wed, 19 Mar 2026 19:29:59 +0000
X-Originating-IP: [203.0.113.45]
Authentication-Results: spf=softfail; dkim=none; dmarc=fail
From: "Marketing Team" <marketing@sketchy.biz>
To: me@outlook.com
Subject: You Won a Prize!
Date: Wed, 19 Mar 2026 15:29:58 -0400
Message-ID: <xyz789@outlook.com>
Reply-To: claim-prize@different-domain.com
List-Unsubscribe: <mailto:unsub@sketchy.biz>
X-Campaign-ID: camp_12345
"""

SAMPLE_HEADERS_MINIMAL = """\
From: bare@example.com
To: me@example.com
Subject: Minimal headers
Date: Wed, 19 Mar 2026 10:00:00 +0000
"""


@pytest.fixture
def gmail_headers():
    return SAMPLE_HEADERS_GMAIL


@pytest.fixture
def outlook_headers():
    return SAMPLE_HEADERS_OUTLOOK


@pytest.fixture
def minimal_headers():
    return SAMPLE_HEADERS_MINIMAL
```

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml email_intel/ tests/
git commit -m "feat: project scaffolding, data models, and test fixtures"
```

---

### Task 2: Header Parser — Core Extraction

**Files:**
- Create: `email_intel/parser.py`
- Create: `tests/test_parser.py`

- [ ] **Step 1: Write failing tests for parser**

```python
# tests/test_parser.py
import email
from email_intel.parser import (
    parse_headers,
    extract_hops,
    extract_originating_ip,
    extract_auth,
    extract_timezone,
    extract_mail_client,
    detect_reply_to_mismatch,
    detect_bulk,
    is_private_ip,
)


def test_parse_headers_returns_email_analysis(gmail_headers):
    result = parse_headers(gmail_headers)
    assert result.from_addr == "sender@example.com"
    assert result.to_addr == "me@gmail.com"
    assert result.subject == "Test Email for Analysis"


def test_extract_hops_gmail(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    hops = extract_hops(msg)
    assert len(hops) == 3
    # After reversed(), hops are chronological: originating hop is first
    # First hop's Received header has [10.0.0.1] (private) as first IP match
    assert hops[0].ip == "10.0.0.1"
    # Second hop has the Google relay IP
    assert hops[1].ip == "209.85.128.182"


def test_extract_originating_ip_from_received(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    hops = extract_hops(msg)
    ip = extract_originating_ip(msg, hops)
    assert ip == "74.125.82.42"


def test_extract_originating_ip_from_x_originating(outlook_headers):
    msg = email.message_from_string(outlook_headers)
    hops = extract_hops(msg)
    ip = extract_originating_ip(msg, hops)
    assert ip == "203.0.113.45"


def test_extract_auth_pass(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    auth = extract_auth(msg)
    assert auth.spf == "pass"
    assert auth.dkim == "pass"
    assert auth.dmarc == "pass"


def test_extract_auth_fail(outlook_headers):
    msg = email.message_from_string(outlook_headers)
    auth = extract_auth(msg)
    assert auth.spf == "softfail"
    assert auth.dmarc == "fail"


def test_extract_timezone(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    offset, name = extract_timezone(msg)
    assert offset == "-0500"


def test_extract_mail_client_x_mailer(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    client = extract_mail_client(msg)
    assert "Apple Mail" in client


def test_extract_mail_client_message_id_fallback(outlook_headers):
    msg = email.message_from_string(outlook_headers)
    client = extract_mail_client(msg)
    assert client == "Outlook"


def test_detect_reply_to_mismatch_no_mismatch(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    assert detect_reply_to_mismatch(msg) is False


def test_detect_reply_to_mismatch_found(outlook_headers):
    msg = email.message_from_string(outlook_headers)
    assert detect_reply_to_mismatch(msg) is True


def test_detect_bulk_not_bulk(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    assert detect_bulk(msg) is False


def test_detect_bulk_detected(outlook_headers):
    msg = email.message_from_string(outlook_headers)
    assert detect_bulk(msg) is True


def test_is_private_ip():
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("74.125.82.42") is False
    assert is_private_ip("::1") is True
    assert is_private_ip("fc00::1") is True
    assert is_private_ip("2607:f8b0:4004::1") is False


def test_parse_headers_minimal(minimal_headers):
    result = parse_headers(minimal_headers)
    assert result.from_addr == "bare@example.com"
    assert result.hops == []
    assert result.originating_ip is None
    assert "No Received headers" in result.flags
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_parser.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'email_intel.parser'`

- [ ] **Step 3: Write `email_intel/parser.py`**

```python
from __future__ import annotations
import email
import ipaddress
import re
from datetime import datetime, timezone
from email.message import Message
from email.utils import parseaddr, parsedate_to_datetime

from email_intel.models import AuthResult, EmailAnalysis, ServerHop

# Regex for extracting IPs from Received headers
_IP_RE = re.compile(
    r"\[?"
    r"("
    r"(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"  # IPv6 full
    r"|::1"  # IPv6 loopback
    r")"
    r"\]?"
)

_RECEIVED_FROM_RE = re.compile(
    r"from\s+([\w\-\.]+)"  # server hostname
)

_RECEIVED_PROTO_RE = re.compile(
    r"with\s+(E?SMTP\w*)", re.IGNORECASE
)

_RECEIVED_DATE_RE = re.compile(
    r";\s*(.+)$", re.MULTILINE
)

# Message-ID domain → client name
_MSGID_CLIENTS: dict[str, str] = {
    "mail.gmail.com": "Gmail",
    "outlook.com": "Outlook",
    "yahoo.com": "Yahoo Mail",
    "icloud.com": "Apple iCloud",
    "protonmail.com": "ProtonMail",
    "fastmail.com": "FastMail",
}

_TZ_NAMES: dict[str, str] = {
    "+0000": "UTC", "-0400": "EDT", "-0500": "EST/CDT",
    "-0600": "CST/MDT", "-0700": "MST/PDT", "-0800": "PST",
    "+0100": "CET", "+0200": "EET", "+0530": "IST",
    "+0800": "CST/SGT", "+0900": "JST/KST", "+1000": "AEST",
}


def is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def extract_hops(msg: Message) -> list[ServerHop]:
    received_headers = msg.get_all("Received", [])
    hops: list[ServerHop] = []

    for header in reversed(received_headers):  # bottom-up = chronological
        header_str = " ".join(header.split())  # normalize whitespace

        server_match = _RECEIVED_FROM_RE.search(header_str)
        server = server_match.group(1) if server_match else "unknown"

        ip_match = _IP_RE.search(header_str)
        ip = ip_match.group(1) if ip_match else None

        proto_match = _RECEIVED_PROTO_RE.search(header_str)
        protocol = proto_match.group(1) if proto_match else None

        date_match = _RECEIVED_DATE_RE.search(header_str)
        timestamp = None
        if date_match:
            try:
                timestamp = parsedate_to_datetime(date_match.group(1).strip())
            except (ValueError, TypeError):
                pass

        hops.append(ServerHop(
            server=server, ip=ip, timestamp=timestamp,
            protocol=protocol, latency_ms=None,
        ))

    # Compute latencies between hops
    for i in range(1, len(hops)):
        if hops[i].timestamp and hops[i - 1].timestamp:
            delta = (hops[i].timestamp - hops[i - 1].timestamp).total_seconds()
            hops[i].latency_ms = round(delta * 1000, 1)

    return hops


def extract_originating_ip(msg: Message, hops: list[ServerHop]) -> str | None:
    x_orig = msg.get("X-Originating-IP", "")
    if x_orig:
        ip_match = _IP_RE.search(x_orig)
        if ip_match:
            ip = ip_match.group(1)
            if not is_private_ip(ip):
                return ip

    # Walk hops from last (originating) to first, find first public IP
    for hop in reversed(hops):
        if hop.ip and not is_private_ip(hop.ip):
            return hop.ip

    return None


def extract_auth(msg: Message) -> AuthResult:
    auth_header = msg.get("Authentication-Results", "")
    if not auth_header:
        return AuthResult()

    auth_lower = auth_header.lower()

    def _find_result(key: str) -> str | None:
        pattern = re.compile(rf"\b{key}=([\w]+)")
        match = pattern.search(auth_lower)
        return match.group(1) if match else None

    return AuthResult(
        spf=_find_result("spf"),
        dkim=_find_result("dkim"),
        dmarc=_find_result("dmarc"),
    )


def extract_timezone(msg: Message) -> tuple[str | None, str | None]:
    date_str = msg.get("Date", "")
    if not date_str:
        return None, None

    match = re.search(r"([+-]\d{4})", date_str)
    offset = match.group(1) if match else None
    name = _TZ_NAMES.get(offset, None) if offset else None
    return offset, name


def extract_mail_client(msg: Message) -> str | None:
    x_mailer = msg.get("X-Mailer")
    if x_mailer:
        return x_mailer.strip()

    user_agent = msg.get("User-Agent")
    if user_agent:
        return user_agent.strip()

    msg_id = msg.get("Message-ID", "")
    at_idx = msg_id.rfind("@")
    if at_idx > 0:
        domain = msg_id[at_idx + 1:].rstrip(">").lower()
        if domain in _MSGID_CLIENTS:
            return _MSGID_CLIENTS[domain]

    return "Unknown"


def detect_reply_to_mismatch(msg: Message) -> bool:
    from_addr = parseaddr(msg.get("From", ""))[1].lower()
    reply_to = parseaddr(msg.get("Reply-To", ""))[1].lower()
    if not reply_to or not from_addr:
        return False
    from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    reply_domain = reply_to.split("@")[-1] if "@" in reply_to else ""
    return from_domain != reply_domain


def detect_bulk(msg: Message) -> bool:
    if msg.get("List-Unsubscribe"):
        return True
    if msg.get("X-Campaign-ID") or msg.get("X-Mailgun-Sid"):
        return True
    if msg.get("Precedence", "").lower() in ("bulk", "list"):
        return True
    return False


def parse_headers(raw_headers: str) -> EmailAnalysis:
    msg = email.message_from_string(raw_headers)

    _, from_addr = parseaddr(msg.get("From", ""))
    _, to_addr = parseaddr(msg.get("To", ""))
    subject = msg.get("Subject")
    message_id = msg.get("Message-ID")

    date = None
    date_str = msg.get("Date")
    if date_str:
        try:
            date = parsedate_to_datetime(date_str)
        except (ValueError, TypeError):
            pass

    hops = extract_hops(msg)
    originating_ip = extract_originating_ip(msg, hops)
    auth = extract_auth(msg)
    tz_offset, tz_name = extract_timezone(msg)
    mail_client = extract_mail_client(msg)
    reply_to_mismatch = detect_reply_to_mismatch(msg)
    is_bulk = detect_bulk(msg)

    flags: list[str] = []
    if not hops:
        flags.append("No Received headers")
    if reply_to_mismatch:
        flags.append("Reply-To domain mismatch")
    if auth.spf and auth.spf not in ("pass",):
        flags.append(f"SPF {auth.spf}")
    if auth.dkim and auth.dkim not in ("pass",):
        flags.append(f"DKIM {auth.dkim}")
    if auth.dmarc and auth.dmarc not in ("pass",):
        flags.append(f"DMARC {auth.dmarc}")

    return EmailAnalysis(
        message_id=message_id,
        from_addr=from_addr or None,
        to_addr=to_addr or None,
        subject=subject,
        date=date,
        timezone_offset=tz_offset,
        timezone_name=tz_name,
        mail_client=mail_client,
        hops=hops,
        originating_ip=originating_ip,
        geo=None,  # filled in by geo module
        auth=auth,
        reply_to_mismatch=reply_to_mismatch,
        is_bulk=is_bulk,
        flags=flags,
    )
```

- [ ] **Step 4: Run tests and verify pass**

Run: `pytest tests/test_parser.py -v`
Expected: All 16 tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/parser.py tests/test_parser.py
git commit -m "feat: header parser — hops, IPs, auth, timezone, client, flags"
```

---

### Task 3: Geolocation — ip-api, MaxMind, SQLite Cache

**Files:**
- Create: `email_intel/geo.py`
- Create: `tests/test_geo.py`

- [ ] **Step 1: Write failing tests for geo module**

```python
# tests/test_geo.py
import sqlite3
import time
from unittest.mock import patch, MagicMock
from email_intel.geo import (
    IpApiProvider,
    MaxMindProvider,
    GeoCache,
    resolve_ip,
    resolve_ips_batch,
)
from email_intel.models import GeoResult


def test_ip_api_single(tmp_path):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "status": "success", "query": "74.125.82.42",
        "city": "Mountain View", "regionName": "California",
        "country": "United States", "countryCode": "US",
        "lat": 37.386, "lon": -122.084,
        "isp": "Google LLC", "org": "Google LLC",
    }
    mock_response.status_code = 200

    with patch("email_intel.geo.requests.get", return_value=mock_response):
        provider = IpApiProvider()
        result = provider.lookup("74.125.82.42")
        assert result.city == "Mountain View"
        assert result.source == "ip-api"


def test_ip_api_batch(tmp_path):
    mock_response = MagicMock()
    mock_response.json.return_value = [
        {"status": "success", "query": "74.125.82.42",
         "city": "Mountain View", "regionName": "California",
         "country": "United States", "countryCode": "US",
         "lat": 37.386, "lon": -122.084, "isp": "Google", "org": "Google"},
        {"status": "success", "query": "203.0.113.45",
         "city": "London", "regionName": "England",
         "country": "United Kingdom", "countryCode": "GB",
         "lat": 51.509, "lon": -0.118, "isp": "Example ISP", "org": "Example"},
    ]
    mock_response.status_code = 200

    with patch("email_intel.geo.requests.post", return_value=mock_response):
        provider = IpApiProvider()
        results = provider.lookup_batch(["74.125.82.42", "203.0.113.45"])
        assert len(results) == 2
        assert results["74.125.82.42"].city == "Mountain View"
        assert results["203.0.113.45"].city == "London"


def test_geo_cache_hit(tmp_path):
    cache = GeoCache(db_path=str(tmp_path / "test_cache.db"))
    geo = GeoResult(
        ip="1.2.3.4", city="Test", region="R", country="US",
        lat=0.0, lon=0.0, isp="ISP", org="Org", source="ip-api",
    )
    cache.put(geo)
    result = cache.get("1.2.3.4")
    assert result is not None
    assert result.city == "Test"


def test_geo_cache_miss(tmp_path):
    cache = GeoCache(db_path=str(tmp_path / "test_cache.db"))
    result = cache.get("9.9.9.9")
    assert result is None


def test_geo_cache_expired(tmp_path):
    cache = GeoCache(db_path=str(tmp_path / "test_cache.db"), ttl_days=1)
    geo = GeoResult(
        ip="1.2.3.4", city="Old", region="R", country="US",
        lat=0.0, lon=0.0, isp="ISP", org="Org", source="ip-api",
    )
    cache.put(geo)
    # Manually expire the entry
    conn = sqlite3.connect(str(tmp_path / "test_cache.db"))
    conn.execute("UPDATE geo_cache SET cached_at = cached_at - 86401")
    conn.commit()
    conn.close()
    result = cache.get("1.2.3.4")
    assert result is None


def test_resolve_ip_uses_cache(tmp_path):
    cache = GeoCache(db_path=str(tmp_path / "test_cache.db"))
    geo = GeoResult(
        ip="1.2.3.4", city="Cached", region="R", country="US",
        lat=0.0, lon=0.0, isp="ISP", org="Org", source="ip-api",
    )
    cache.put(geo)

    result = resolve_ip("1.2.3.4", cache=cache)
    assert result.city == "Cached"  # no network call


def test_resolve_ips_batch_deduplicates(tmp_path):
    cache = GeoCache(db_path=str(tmp_path / "test_cache.db"))

    mock_response = MagicMock()
    mock_response.json.return_value = [{
        "status": "success", "query": "1.2.3.4",
        "city": "Test", "regionName": "R",
        "country": "US", "countryCode": "US",
        "lat": 0.0, "lon": 0.0, "isp": "ISP", "org": "Org",
    }]
    mock_response.status_code = 200

    with patch("email_intel.geo.requests.post", return_value=mock_response):
        results = resolve_ips_batch(
            ["1.2.3.4", "1.2.3.4", "1.2.3.4"],
            cache=cache,
        )
    assert len(results) == 1
    assert results["1.2.3.4"].city == "Test"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_geo.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `email_intel/geo.py`**

```python
from __future__ import annotations
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Protocol

import requests

from email_intel.models import GeoResult

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_DIR = Path.home() / ".email-intel"


class GeoProvider(Protocol):
    def lookup(self, ip: str) -> GeoResult | None: ...
    def lookup_batch(self, ips: list[str]) -> dict[str, GeoResult]: ...


class IpApiProvider:
    BASE_URL = "http://ip-api.com"
    MAX_RETRIES = 3

    def _request_with_retry(self, method: str, url: str, **kwargs) -> requests.Response | None:
        """Make HTTP request with exponential backoff on 429."""
        for attempt in range(self.MAX_RETRIES):
            try:
                resp = getattr(requests, method)(url, **kwargs)
                if resp.status_code == 429:
                    wait = 2 ** (attempt + 1)
                    logger.warning("ip-api rate limited, retrying in %ds...", wait)
                    time.sleep(wait)
                    continue
                return resp
            except requests.RequestException as e:
                logger.warning("ip-api request failed (attempt %d): %s", attempt + 1, e)
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
        return None

    def lookup(self, ip: str) -> GeoResult | None:
        resp = self._request_with_retry(
            "get",
            f"{self.BASE_URL}/json/{ip}",
            params={"fields": "status,query,city,regionName,country,countryCode,lat,lon,isp,org"},
            timeout=10,
        )
        if not resp:
            return None
        try:
            data = resp.json()
            if data.get("status") != "success":
                return None
            return self._to_geo(data)
        except ValueError as e:
            logger.warning("ip-api lookup failed for %s: %s", ip, e)
            return None

    def lookup_batch(self, ips: list[str]) -> dict[str, GeoResult]:
        results: dict[str, GeoResult] = {}
        # Batch in chunks of 100
        for i in range(0, len(ips), 100):
            chunk = ips[i:i + 100]
            resp = self._request_with_retry(
                "post",
                f"{self.BASE_URL}/batch",
                json=[{"query": ip, "fields": "status,query,city,regionName,country,countryCode,lat,lon,isp,org"} for ip in chunk],
                timeout=30,
            )
            if resp:
                try:
                    for item in resp.json():
                        if item.get("status") == "success":
                            geo = self._to_geo(item)
                            results[geo.ip] = geo
                except ValueError as e:
                    logger.warning("ip-api batch parse failed: %s", e)

            # Rate limit: 15 batch requests/min
            if i + 100 < len(ips):
                time.sleep(4)

        return results

    @staticmethod
    def _to_geo(data: dict) -> GeoResult:
        return GeoResult(
            ip=data["query"],
            city=data.get("city"),
            region=data.get("regionName"),
            country=data.get("countryCode") or data.get("country"),
            lat=data.get("lat"),
            lon=data.get("lon"),
            isp=data.get("isp"),
            org=data.get("org"),
            source="ip-api",
        )


class MaxMindProvider:
    def __init__(self, db_path: str):
        try:
            import geoip2.database
            self._reader = geoip2.database.Reader(db_path)
        except ImportError:
            raise ImportError("geoip2 not installed. Install with: pip install email-intel[maxmind]")

    def lookup(self, ip: str) -> GeoResult | None:
        try:
            resp = self._reader.city(ip)
            return GeoResult(
                ip=ip,
                city=resp.city.name,
                region=resp.subdivisions.most_specific.name if resp.subdivisions else None,
                country=resp.country.iso_code,
                lat=resp.location.latitude,
                lon=resp.location.longitude,
                isp=None,
                org=getattr(resp, "autonomous_system_organization", None) if hasattr(resp, "autonomous_system_organization") else None,
                source="maxmind",
            )
        except Exception as e:
            logger.warning("MaxMind lookup failed for %s: %s", ip, e)
            return None

    def lookup_batch(self, ips: list[str]) -> dict[str, GeoResult]:
        results: dict[str, GeoResult] = {}
        for ip in ips:
            geo = self.lookup(ip)
            if geo:
                results[ip] = geo
        return results


class GeoCache:
    def __init__(self, db_path: str | None = None, ttl_days: int = 30):
        self._db_path = db_path or str(_DEFAULT_CACHE_DIR / "geo_cache.db")
        self._ttl_seconds = ttl_days * 86400
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self._db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS geo_cache (
                ip TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                cached_at INTEGER NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def get(self, ip: str) -> GeoResult | None:
        try:
            conn = sqlite3.connect(self._db_path)
            row = conn.execute(
                "SELECT data, cached_at FROM geo_cache WHERE ip = ?", (ip,)
            ).fetchone()
            conn.close()
            if not row:
                return None
            data, cached_at = row
            if time.time() - cached_at > self._ttl_seconds:
                return None
            d = json.loads(data)
            return GeoResult(**d)
        except (sqlite3.Error, json.JSONDecodeError) as e:
            logger.warning("Cache read error: %s", e)
            return None

    def put(self, geo: GeoResult):
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT OR REPLACE INTO geo_cache (ip, data, cached_at) VALUES (?, ?, ?)",
                (geo.ip, json.dumps(geo.__dict__), int(time.time())),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.warning("Cache write error: %s", e)


def _get_provider(provider_name: str = "ip-api", maxmind_path: str | None = None) -> GeoProvider:
    if provider_name == "maxmind" and maxmind_path:
        return MaxMindProvider(maxmind_path)
    return IpApiProvider()


def resolve_ip(
    ip: str,
    cache: GeoCache | None = None,
    provider: GeoProvider | None = None,
) -> GeoResult | None:
    if cache:
        cached = cache.get(ip)
        if cached:
            return cached

    prov = provider or IpApiProvider()
    result = prov.lookup(ip)

    if result and cache:
        cache.put(result)

    return result


def resolve_ips_batch(
    ips: list[str],
    cache: GeoCache | None = None,
    provider: GeoProvider | None = None,
) -> dict[str, GeoResult]:
    unique_ips = list(set(ips))
    results: dict[str, GeoResult] = {}
    uncached: list[str] = []

    if cache:
        for ip in unique_ips:
            cached = cache.get(ip)
            if cached:
                results[ip] = cached
            else:
                uncached.append(ip)
    else:
        uncached = unique_ips

    if uncached:
        prov = provider or IpApiProvider()
        fetched = prov.lookup_batch(uncached)
        for ip, geo in fetched.items():
            results[ip] = geo
            if cache:
                cache.put(geo)

    return results
```

- [ ] **Step 4: Run tests and verify pass**

Run: `pytest tests/test_geo.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/geo.py tests/test_geo.py
git commit -m "feat: geolocation — ip-api, MaxMind, SQLite cache with batch support"
```

---

### Task 4: Config Module

**Files:**
- Create: `email_intel/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_config.py
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
```

- [ ] **Step 2: Run to verify fail**

Run: `pytest tests/test_config.py -v`
Expected: FAIL

- [ ] **Step 3: Write `email_intel/config.py`**

```python
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
        tomllib = None  # type: ignore

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

    # Env var overrides
    if os.environ.get("MAXMIND_DB_PATH"):
        cfg.maxmind_db_path = os.environ["MAXMIND_DB_PATH"]
    if os.environ.get("GMAIL_CREDENTIALS_PATH"):
        cfg.gmail_credentials_path = os.environ["GMAIL_CREDENTIALS_PATH"]

    return cfg
```

- [ ] **Step 4: Run tests and verify pass**

Run: `pytest tests/test_config.py -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/config.py tests/test_config.py
git commit -m "feat: config module — TOML file + env var overrides"
```

---

### Task 5: Apple Mail .emlx Parser

**Files:**
- Create: `email_intel/apple_mail.py`
- Create: `tests/test_apple_mail.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_apple_py
import os
from pathlib import Path
from datetime import datetime, timezone
from email_intel.apple_mail import parse_emlx, find_emlx_files


def _create_emlx(path: Path, headers: str) -> Path:
    """Create a minimal .emlx file with the given headers."""
    body = headers + "\nBody text here.\n"
    byte_count = len(body.encode("utf-8"))
    content = f"{byte_count}\n{body}"
    # Append minimal plist trailer
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
    # Simulate Apple Mail directory structure
    mail_dir = tmp_path / "Library" / "Mail" / "V10" / "account" / "INBOX.mbox"
    _create_emlx(mail_dir / "1.emlx", "From: a@test.com\nDate: Wed, 19 Mar 2026 10:00:00 +0000\n")
    _create_emlx(mail_dir / "2.emlx", "From: b@test.com\nDate: Wed, 18 Mar 2026 10:00:00 +0000\n")

    files = find_emlx_files(base_dir=str(tmp_path / "Library" / "Mail"))
    assert len(files) == 2


def test_find_emlx_files_empty(tmp_path):
    files = find_emlx_files(base_dir=str(tmp_path / "nonexistent"))
    assert files == []
```

- [ ] **Step 2: Run to verify fail**

Run: `pytest tests/test_apple_mail.py -v`
Expected: FAIL

- [ ] **Step 3: Write `email_intel/apple_mail.py`**

```python
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

            # Extract just headers (before first blank line)
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

        # Filter by mtime for --days
        if cutoff:
            mtime = datetime.fromtimestamp(emlx_path.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                continue

        # If we need content filters, parse headers
        if from_filter or query:
            headers = parse_emlx(str(emlx_path))
            if headers is None:
                continue

            if from_filter:
                # Match only the From header line, not all headers
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
```

- [ ] **Step 4: Run tests and verify pass**

Run: `pytest tests/test_apple_mail.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/apple_mail.py tests/test_apple_mail.py
git commit -m "feat: Apple Mail .emlx parser and file discovery"
```

---

### Task 6: Reporter — Rich Terminal + JSON/CSV Export

**Files:**
- Create: `email_intel/reporter.py`
- Create: `tests/test_reporter.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_reporter.py
import json
import csv
import io
from datetime import datetime, timezone
from email_intel.reporter import (
    render_analysis,
    render_scan_summary,
    export_json,
    export_csv,
    build_scan_summary,
)
from email_intel.models import (
    EmailAnalysis, AuthResult, GeoResult, ServerHop, ScanSummary,
)


def _make_analysis(**overrides) -> EmailAnalysis:
    defaults = dict(
        message_id="<test@mail.gmail.com>",
        from_addr="sender@example.com",
        to_addr="me@test.com",
        subject="Test",
        date=datetime(2026, 3, 19, 14, 30, 0, tzinfo=timezone.utc),
        timezone_offset="-0500",
        timezone_name="EST",
        mail_client="Gmail",
        hops=[],
        originating_ip="74.125.82.42",
        geo=GeoResult(
            ip="74.125.82.42", city="Mountain View", region="California",
            country="US", lat=37.386, lon=-122.084,
            isp="Google LLC", org="Google LLC", source="ip-api",
        ),
        auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"),
        reply_to_mismatch=False,
        is_bulk=False,
        flags=[],
    )
    defaults.update(overrides)
    return EmailAnalysis(**defaults)


def test_render_analysis_returns_string():
    analysis = _make_analysis()
    output = render_analysis(analysis)
    assert "sender@example.com" in output
    assert "Mountain View" in output
    assert "SPF" in output


def test_render_analysis_with_flags():
    analysis = _make_analysis(flags=["Reply-To domain mismatch", "DMARC fail"])
    output = render_analysis(analysis)
    assert "Reply-To domain mismatch" in output


def test_build_scan_summary():
    emails = [
        _make_analysis(from_addr="a@test.com", mail_client="Gmail"),
        _make_analysis(from_addr="b@test.com", mail_client="Outlook"),
        _make_analysis(from_addr="c@test.com", mail_client="Gmail",
                       flags=["DMARC fail"]),
    ]
    summary = build_scan_summary(emails)
    assert summary.total_messages == 3
    assert ("Mountain View, US", 3) in summary.top_locations
    assert summary.client_breakdown["Gmail"] == 2
    assert summary.client_breakdown["Outlook"] == 1
    assert len(summary.flagged_messages) == 1


def test_export_json():
    analysis = _make_analysis()
    output = export_json([analysis])
    data = json.loads(output)
    assert len(data) == 1
    assert data[0]["from_addr"] == "sender@example.com"


def test_export_csv():
    analysis = _make_analysis()
    output = export_csv([analysis])
    reader = csv.DictReader(io.StringIO(output))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["from_addr"] == "sender@example.com"
    assert rows[0]["geo_city"] == "Mountain View"
```

- [ ] **Step 2: Run to verify fail**

Run: `pytest tests/test_reporter.py -v`
Expected: FAIL

- [ ] **Step 3: Write `email_intel/reporter.py`**

```python
from __future__ import annotations
import csv
import io
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from email_intel.models import EmailAnalysis, ScanSummary


def render_analysis(analysis: EmailAnalysis) -> str:
    console = Console(file=io.StringIO(), force_terminal=True, width=80)

    # Header
    console.print(Panel.fit(
        f"[bold]From:[/bold] {analysis.from_addr or 'Unknown'}\n"
        f"[bold]To:[/bold] {analysis.to_addr or 'Unknown'}\n"
        f"[bold]Subject:[/bold] {analysis.subject or '(none)'}\n"
        f"[bold]Date:[/bold] {analysis.date or 'Unknown'} "
        f"UTC{analysis.timezone_offset or '?'}"
        f"{f' ({analysis.timezone_name})' if analysis.timezone_name else ''}",
        title="Email Analysis",
    ))

    # Origin
    if analysis.originating_ip:
        geo = analysis.geo
        origin_text = f"[bold]IP:[/bold] {analysis.originating_ip}"
        if geo:
            origin_text += f" → {geo.city or '?'}, {geo.region or '?'}, {geo.country or '?'}"
            if geo.isp:
                origin_text += f" ({geo.isp})"
        origin_text += f"\n[bold]Client:[/bold] {analysis.mail_client or 'Unknown'}"
        console.print(Panel.fit(origin_text, title="Origin"))

    # Auth
    def _auth_icon(val: str | None) -> str:
        if val == "pass":
            return "✓"
        elif val in ("fail", "softfail"):
            return "✗"
        return "?"

    auth = analysis.auth
    console.print(Panel.fit(
        f"SPF {_auth_icon(auth.spf)} {auth.spf or 'none'}  "
        f"DKIM {_auth_icon(auth.dkim)} {auth.dkim or 'none'}  "
        f"DMARC {_auth_icon(auth.dmarc)} {auth.dmarc or 'none'}",
        title="Auth",
    ))

    # Hops
    if analysis.hops:
        table = Table(title=f"Server Hops ({len(analysis.hops)})")
        table.add_column("#", style="dim", width=3)
        table.add_column("Server")
        table.add_column("IP")
        table.add_column("Protocol")
        table.add_column("Latency")

        for i, hop in enumerate(analysis.hops, 1):
            latency = f"{hop.latency_ms:.0f}ms" if hop.latency_ms is not None else "-"
            table.add_row(
                str(i), hop.server, hop.ip or "-",
                hop.protocol or "-", latency,
            )
        console.print(table)

    # Flags
    if analysis.flags:
        flags_text = "\n".join(f"⚠ {f}" for f in analysis.flags)
        console.print(Panel.fit(flags_text, title="Flags", border_style="yellow"))

    output = console.file.getvalue()
    return output


def render_scan_summary(summary: ScanSummary) -> str:
    console = Console(file=io.StringIO(), force_terminal=True, width=100)

    console.print(f"\n[bold]Scanned {summary.total_messages} messages[/bold]")

    # Top locations
    if summary.top_locations:
        table = Table(title="Top Sender Locations")
        table.add_column("Location")
        table.add_column("Count", justify="right")
        for loc, count in summary.top_locations[:10]:
            table.add_row(loc, str(count))
        console.print(table)

    # Timezone distribution
    if summary.timezone_distribution:
        table = Table(title="Timezone Distribution")
        table.add_column("Timezone")
        table.add_column("Count", justify="right")
        for tz, count in sorted(summary.timezone_distribution.items(), key=lambda x: -x[1]):
            table.add_row(tz, str(count))
        console.print(table)

    # Client breakdown
    if summary.client_breakdown:
        table = Table(title="Mail Clients")
        table.add_column("Client")
        table.add_column("Count", justify="right")
        for client, count in sorted(summary.client_breakdown.items(), key=lambda x: -x[1]):
            table.add_row(client, str(count))
        console.print(table)

    # Flagged
    if summary.flagged_messages:
        console.print(f"\n[yellow bold]⚠ {len(summary.flagged_messages)} flagged messages:[/yellow bold]")
        for msg in summary.flagged_messages[:20]:
            flags = ", ".join(msg.flags)
            console.print(f"  • {msg.from_addr or '?'} — {msg.subject or '(no subject)'} [{flags}]")

    return console.file.getvalue()


def build_scan_summary(emails: list[EmailAnalysis]) -> ScanSummary:
    if not emails:
        now = datetime.now(tz=timezone.utc)
        return ScanSummary(total_messages=0, date_range=(now, now))

    dates = [e.date for e in emails if e.date]
    date_range = (min(dates), max(dates)) if dates else (
        datetime.now(tz=timezone.utc), datetime.now(tz=timezone.utc)
    )

    # Locations
    loc_counter: Counter[str] = Counter()
    for e in emails:
        if e.geo and e.geo.city and e.geo.country:
            loc_counter[f"{e.geo.city}, {e.geo.country}"] += 1

    # Timezones
    tz_counter: Counter[str] = Counter()
    for e in emails:
        tz_label = e.timezone_name or e.timezone_offset
        if tz_label:
            tz_counter[tz_label] += 1

    # Clients
    client_counter: Counter[str] = Counter()
    for e in emails:
        if e.mail_client:
            client_counter[e.mail_client] += 1

    flagged = [e for e in emails if e.flags]

    return ScanSummary(
        total_messages=len(emails),
        date_range=date_range,
        top_locations=loc_counter.most_common(20),
        timezone_distribution=dict(tz_counter),
        client_breakdown=dict(client_counter),
        flagged_messages=flagged,
        emails=emails,
    )


def _analysis_to_flat(a: EmailAnalysis) -> dict:
    return {
        "message_id": a.message_id,
        "from_addr": a.from_addr,
        "to_addr": a.to_addr,
        "subject": a.subject,
        "date": a.date.isoformat() if a.date else None,
        "timezone_offset": a.timezone_offset,
        "timezone_name": a.timezone_name,
        "mail_client": a.mail_client,
        "originating_ip": a.originating_ip,
        "geo_city": a.geo.city if a.geo else None,
        "geo_region": a.geo.region if a.geo else None,
        "geo_country": a.geo.country if a.geo else None,
        "geo_lat": a.geo.lat if a.geo else None,
        "geo_lon": a.geo.lon if a.geo else None,
        "geo_isp": a.geo.isp if a.geo else None,
        "geo_org": a.geo.org if a.geo else None,
        "spf": a.auth.spf,
        "dkim": a.auth.dkim,
        "dmarc": a.auth.dmarc,
        "reply_to_mismatch": a.reply_to_mismatch,
        "is_bulk": a.is_bulk,
        "hop_count": len(a.hops),
        "flags": "; ".join(a.flags) if a.flags else "",
    }


def export_json(emails: list[EmailAnalysis]) -> str:
    return json.dumps([_analysis_to_flat(e) for e in emails], indent=2)


def export_csv(emails: list[EmailAnalysis]) -> str:
    if not emails:
        return ""
    rows = [_analysis_to_flat(e) for e in emails]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()
```

- [ ] **Step 4: Run tests and verify pass**

Run: `pytest tests/test_reporter.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/reporter.py tests/test_reporter.py
git commit -m "feat: reporter — rich terminal output, JSON/CSV export, scan summary builder"
```

---

### Task 7: Gmail Client (OAuth2 + Header Fetching)

**Files:**
- Create: `email_intel/gmail_client.py`

Gmail client is integration-heavy (OAuth browser flow, real API). We write the module with clean interfaces and test it manually after wiring up credentials. Unit tests mock the Google API client.

- [ ] **Step 1: Write `email_intel/gmail_client.py`**

```python
from __future__ import annotations
import base64
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from email_intel.config import Config

logger = logging.getLogger(__name__)

MAX_RETRIES = 3


def _get_gmail_service(config: Config):
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    token_path = Path(config.gmail_token_path)
    creds_path = Path(config.gmail_credentials_path)
    scopes = ["https://www.googleapis.com/auth/gmail.readonly"]

    creds = None
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), scopes)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not creds_path.exists():
                raise FileNotFoundError(
                    f"Gmail credentials not found at {creds_path}. "
                    "Download from Google Cloud Console and place at "
                    "~/.email-intel/credentials.json"
                )
            flow = InstalledAppFlow.from_client_secrets_file(
                str(creds_path), scopes
            )
            creds = flow.run_local_server(port=8080)

        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def _execute_with_retry(request):
    """Execute a Google API request with exponential backoff on 429."""
    from googleapiclient.errors import HttpError
    for attempt in range(MAX_RETRIES):
        try:
            return request.execute()
        except HttpError as e:
            if e.resp.status == 429 and attempt < MAX_RETRIES - 1:
                wait = 2 ** (attempt + 1)
                logger.warning("Gmail API rate limited, retrying in %ds...", wait)
                time.sleep(wait)
            else:
                raise


def _headers_from_metadata(payload: dict) -> str:
    """Reconstruct raw headers string from Gmail metadata payload."""
    headers = payload.get("headers", [])
    return "\n".join(f"{h['name']}: {h['value']}" for h in headers)


def gmail_auth(config: Config) -> bool:
    try:
        service = _get_gmail_service(config)
        profile = service.users().getProfile(userId="me").execute()
        logger.info("Authenticated as %s", profile.get("emailAddress"))
        return True
    except Exception as e:
        logger.error("Gmail authentication failed: %s", e)
        return False


def fetch_gmail_headers(
    config: Config,
    message_id: str | None = None,
    days: int | None = None,
    from_filter: str | None = None,
    query: str | None = None,
    limit: int = 500,
) -> list[str]:
    service = _get_gmail_service(config)

    if message_id:
        # Single message: use raw format to get all headers including Received
        msg = _execute_with_retry(
            service.users().messages().get(
                userId="me", id=message_id, format="raw"
            )
        )
        raw = base64.urlsafe_b64decode(msg["raw"]).decode("utf-8", errors="replace")
        header_end = raw.find("\r\n\r\n")
        if header_end < 0:
            header_end = raw.find("\n\n")
        return [raw[:header_end] if header_end > 0 else raw]

    # Build search query
    parts: list[str] = []
    if days:
        after_date = (datetime.now(tz=timezone.utc) - timedelta(days=days)).strftime("%Y/%m/%d")
        parts.append(f"after:{after_date}")
    if from_filter:
        parts.append(f"from:{from_filter}")
    if query:
        parts.append(query)

    search_query = " ".join(parts) if parts else "in:inbox"

    # Fetch message IDs
    all_ids: list[str] = []
    page_token = None
    fetch_limit = limit if limit > 0 else 10000

    while len(all_ids) < fetch_limit:
        batch_size = min(100, fetch_limit - len(all_ids))
        result = _execute_with_retry(
            service.users().messages().list(
                userId="me", q=search_query,
                maxResults=batch_size, pageToken=page_token,
            )
        )

        messages = result.get("messages", [])
        all_ids.extend(m["id"] for m in messages)

        page_token = result.get("nextPageToken")
        if not page_token:
            break

    # Fetch headers for each message using metadata format (headers only, no body)
    headers_list: list[str] = []
    for msg_id in all_ids:
        try:
            msg = _execute_with_retry(
                service.users().messages().get(
                    userId="me", id=msg_id, format="metadata",
                    metadataHeaders=["From", "To", "Subject", "Date", "Message-ID",
                                     "Received", "Authentication-Results", "X-Mailer",
                                     "User-Agent", "Reply-To", "X-Originating-IP",
                                     "List-Unsubscribe", "X-Campaign-ID", "Precedence",
                                     "Delivered-To", "Content-Type"],
                )
            )
            headers_str = _headers_from_metadata(msg.get("payload", {}))
            if headers_str:
                headers_list.append(headers_str)
        except Exception as e:
            logger.warning("Failed to fetch message %s: %s", msg_id, e)

    return headers_list
```

- [ ] **Step 2: Commit**

```bash
git add email_intel/gmail_client.py
git commit -m "feat: Gmail client — OAuth2 auth flow + header fetching"
```

---

### Task 8: CLI — Click Commands

**Files:**
- Create: `email_intel/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_cli.py
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
```

- [ ] **Step 2: Run to verify fail**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL

- [ ] **Step 3: Write `email_intel/cli.py`**

```python
from __future__ import annotations
import sys
import logging

import click
from rich.console import Console

from email_intel import __version__
from email_intel.config import load_config
from email_intel.parser import parse_headers, is_private_ip
from email_intel.geo import GeoCache, resolve_ip, resolve_ips_batch, IpApiProvider, MaxMindProvider
from email_intel.reporter import (
    render_analysis, render_scan_summary,
    build_scan_summary, export_json, export_csv,
)

console = Console()
logger = logging.getLogger("email_intel")


def _get_provider(cfg):
    if cfg.geo_provider == "maxmind" and cfg.maxmind_db_path:
        return MaxMindProvider(cfg.maxmind_db_path)
    return IpApiProvider()


def _analyze_single(raw_headers: str, cfg, fmt: str, output_path: str | None):
    analysis = parse_headers(raw_headers)

    # Geo lookup
    if analysis.originating_ip and not is_private_ip(analysis.originating_ip):
        cache = GeoCache(db_path=cfg.cache_db_path)
        provider = _get_provider(cfg)
        analysis.geo = resolve_ip(analysis.originating_ip, cache=cache, provider=provider)

    if fmt == "json":
        text = export_json([analysis])
    elif fmt == "csv":
        text = export_csv([analysis])
    else:
        text = render_analysis(analysis)

    if output_path:
        with open(output_path, "w") as f:
            f.write(text)
        console.print(f"Output written to {output_path}")
    else:
        click.echo(text)


@click.group()
@click.version_option(version=__version__)
def main():
    """Email Intel — Personal inbox intelligence."""
    pass


@main.command()
@click.option("--file", "file_path", type=click.Path(exists=True), help="Path to .emlx or raw header file")
@click.option("--gmail-id", help="Gmail message ID to analyze")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "csv"]), default="table")
@click.option("-o", "--output", "output_path", help="Output file path")
def analyze(file_path, gmail_id, fmt, output_path):
    """Analyze a single email's headers."""
    cfg = load_config()

    if gmail_id:
        try:
            from email_intel.gmail_client import fetch_gmail_headers
            headers_list = fetch_gmail_headers(cfg, message_id=gmail_id)
            if not headers_list:
                console.print("[red]No message found with that ID.[/red]")
                sys.exit(1)
            _analyze_single(headers_list[0], cfg, fmt, output_path)
        except ImportError:
            console.print("[red]Gmail dependencies not installed. Run: pip install email-intel[gmail][/red]")
            sys.exit(1)
        return

    if file_path:
        # Check if .emlx
        if file_path.endswith(".emlx"):
            from email_intel.apple_mail import parse_emlx
            raw = parse_emlx(file_path)
            if raw is None:
                console.print(f"[red]Failed to parse {file_path}[/red]")
                sys.exit(1)
        else:
            with open(file_path) as f:
                raw = f.read()
        _analyze_single(raw, cfg, fmt, output_path)
        return

    # stdin / interactive paste
    stdin = click.get_text_stream("stdin")
    if not stdin.isatty():
        raw = stdin.read()
    else:
        console.print("Paste email headers (press Ctrl+D when done):")
        raw = stdin.read()

    if not raw.strip():
        console.print("[red]No headers provided.[/red]")
        sys.exit(1)

    _analyze_single(raw, cfg, fmt, output_path)


@main.command()
@click.option("--source", type=click.Choice(["gmail", "apple-mail"]), required=True)
@click.option("--days", type=int, default=None, help="Scan last N days")
@click.option("--from", "from_filter", help="Filter by sender")
@click.option("--query", help="Search query")
@click.option("--limit", type=int, default=None, help="Max messages (0=unlimited)")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "csv"]), default="table")
@click.option("-o", "--output", "output_path", help="Output file path")
def scan(source, days, from_filter, query, limit, fmt, output_path):
    """Bulk scan inbox for patterns."""
    cfg = load_config()
    days = days or cfg.default_days
    limit = limit if limit is not None else cfg.default_limit

    from rich.progress import Progress

    # Collect raw headers
    if source == "gmail":
        try:
            from email_intel.gmail_client import fetch_gmail_headers
            console.print(f"Fetching Gmail messages (last {days} days, limit {limit})...")
            raw_headers_list = fetch_gmail_headers(
                cfg, days=days, from_filter=from_filter, query=query, limit=limit,
            )
        except ImportError:
            console.print("[red]Gmail dependencies not installed. Run: pip install email-intel[gmail][/red]")
            sys.exit(1)
    else:  # apple-mail
        from email_intel.apple_mail import find_emlx_files, parse_emlx
        console.print(f"Scanning Apple Mail (last {days} days)...")
        files = find_emlx_files(days=days, from_filter=from_filter, query=query)
        if limit > 0:
            files = files[:limit]
        raw_headers_list = []
        for f in files:
            parsed = parse_emlx(f)
            if parsed:
                raw_headers_list.append(parsed)

    if not raw_headers_list:
        console.print("No messages found.")
        sys.exit(0)

    # Parse all
    analyses = []
    with Progress() as progress:
        task = progress.add_task("Parsing headers...", total=len(raw_headers_list))
        for raw in raw_headers_list:
            analyses.append(parse_headers(raw))
            progress.advance(task)

    # Geo resolve all originating IPs
    ips_to_resolve = [
        a.originating_ip for a in analyses
        if a.originating_ip and not is_private_ip(a.originating_ip)
    ]

    if ips_to_resolve:
        cache = GeoCache(db_path=cfg.cache_db_path)
        provider = _get_provider(cfg)
        console.print(f"Resolving {len(set(ips_to_resolve))} unique IPs...")
        geo_map = resolve_ips_batch(ips_to_resolve, cache=cache, provider=provider)
        for a in analyses:
            if a.originating_ip and a.originating_ip in geo_map:
                a.geo = geo_map[a.originating_ip]

    # Output
    summary = build_scan_summary(analyses)

    if fmt == "json":
        text = export_json(analyses)
    elif fmt == "csv":
        text = export_csv(analyses)
    else:
        text = render_scan_summary(summary)

    if output_path:
        with open(output_path, "w") as f:
            f.write(text)
        console.print(f"Output written to {output_path}")
    else:
        click.echo(text)


@main.command()
def auth():
    """Authenticate with Gmail (OAuth2)."""
    cfg = load_config()
    try:
        from email_intel.gmail_client import gmail_auth
        if gmail_auth(cfg):
            console.print("[green]✓ Authenticated successfully.[/green]")
        else:
            console.print("[red]✗ Authentication failed.[/red]")
            sys.exit(1)
    except ImportError:
        console.print("[red]Gmail dependencies not installed. Run: pip install email-intel[gmail][/red]")
        sys.exit(1)
```

- [ ] **Step 4: Run tests and verify pass**

Run: `pytest tests/test_cli.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/cli.py tests/test_cli.py
git commit -m "feat: CLI — analyze, scan, auth commands with Click"
```

---

### Task 9: Integration Test + Final Polish

**Files:**
- Modify: `tests/conftest.py` (add integration fixture if needed)

- [ ] **Step 1: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: All tests PASS

- [ ] **Step 2: Test CLI manually with real headers**

```bash
# Paste mode
echo "$SAMPLE_HEADERS" | email-intel analyze

# JSON export
echo "$SAMPLE_HEADERS" | email-intel analyze --format json
```

- [ ] **Step 3: Fix any issues found**

- [ ] **Step 4: Run full test suite again**

Run: `pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "test: integration tests and final polish"
```

- [ ] **Step 6: Push to GitHub**

```bash
git push origin main
```
