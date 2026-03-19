# Email Intel — Design Spec

## Overview

Standalone Python CLI tool for personal inbox intelligence. Parses email headers to extract sender location, client fingerprints, authentication status, and communication patterns across Gmail and Apple Mail.

## Goals

- Analyze individual emails for full metadata breakdown (origin IP, geolocation, client, auth, server hops)
- Bulk scan inbox to surface patterns (sender locations, timezones, clients, flagged messages)
- Support three input sources: Gmail API, Apple Mail .emlx files, raw header paste
- Export results as terminal tables, JSON, or CSV

## Architecture

```
email-intel/
├── cli.py              # Click CLI entry point (analyze / scan subcommands)
├── parser.py           # Header parsing (IPs, timezone, client, server hops, auth)
├── geo.py              # IP geolocation (ip-api default, MaxMind optional)
├── gmail_client.py     # Gmail OAuth2 integration (readonly)
├── apple_mail.py       # .emlx file scanner
├── reporter.py         # Output formatting (terminal tables, JSON, CSV export)
├── models.py           # Dataclasses for parsed results
└── requirements.txt
```

### Dependencies

- `click` — CLI framework
- `rich` — terminal tables, progress bars
- `google-auth-oauthlib` + `google-api-python-client` — Gmail API
- `geoip2` — MaxMind GeoLite2 (optional)
- `requests` — ip-api.com

## Components

### Header Parsing (`parser.py`)

Extracts from each email:

- **Server hop chain** — every `Received:` header parsed into: server name, IP, timestamp, protocol (ESMTP/TLS)
- **Originating IP** — last `Received:` header + `X-Originating-IP` if present
- **Sender timezone** — from `Date:` header offset (e.g., `-0500` → `UTC-5 / EST`)
- **Mail client** — `X-Mailer`, `User-Agent`, or fingerprinted from `Message-ID` domain and MIME structure
- **Auth results** — `Authentication-Results` header → SPF pass/fail, DKIM pass/fail, DMARC alignment
- **Reply-To mismatch** — flag when `Reply-To` differs from `From`
- **List headers** — `List-Unsubscribe`, `X-Campaign-ID` to detect bulk/marketing mail

Private/internal IPs (IPv4: `10.x`, `192.168.x`, `172.16-31.x`; IPv6: `fc00::/7`, `::1`) are labeled but skipped for geolocation. Parser handles both IPv4 and IPv6 addresses in `Received:` headers.

### Data Models (`models.py`)

```python
@dataclass
class ServerHop:
    server: str           # hostname from Received header
    ip: str | None        # IPv4 or IPv6, None if not present
    timestamp: datetime | None
    protocol: str | None  # ESMTP, ESMTPS, etc.
    latency_ms: float | None  # delta from previous hop

@dataclass
class AuthResult:
    spf: str | None       # pass, fail, softfail, neutral, none
    dkim: str | None      # pass, fail, none
    dmarc: str | None     # pass, fail, none

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
    source: str           # "ip-api" or "maxmind"

@dataclass
class EmailAnalysis:
    message_id: str | None
    from_addr: str | None
    to_addr: str | None
    subject: str | None
    date: datetime | None
    timezone_offset: str | None   # e.g. "-0500"
    timezone_name: str | None     # e.g. "EST" (best-effort)
    mail_client: str | None       # X-Mailer / User-Agent / fingerprint
    hops: list[ServerHop]
    originating_ip: str | None
    geo: GeoResult | None
    auth: AuthResult
    reply_to_mismatch: bool       # Reply-To differs from From
    is_bulk: bool                 # marketing/list headers detected
    flags: list[str]              # human-readable warnings

@dataclass
class ScanSummary:
    total_messages: int
    date_range: tuple[datetime, datetime]
    top_locations: list[tuple[str, int]]      # (city/country, count)
    timezone_distribution: dict[str, int]
    client_breakdown: dict[str, int]
    flagged_messages: list[EmailAnalysis]
    emails: list[EmailAnalysis]               # all parsed results
```

### Geolocation (`geo.py`)

Two providers behind a common interface:

- **ip-api.com (default)** — uses the batch endpoint `POST http://ip-api.com/batch` (up to 100 IPs per request) for scan mode, single `GET` for analyze mode. No API key needed. Rate limited to 15 batch requests/min. **Note:** free tier is HTTP only — IP addresses are sent in plaintext. For sensitive analysis, prefer MaxMind.
- **MaxMind GeoLite2 (optional)** — set `MAXMIND_DB_PATH` env var or configure in `~/.email-intel/config.toml`. Instant local lookups, no rate limits, no network exposure. Falls back to ip-api if not configured.

**Caching:** SQLite cache at `~/.email-intel/geo_cache.db`. 30-day TTL. Both providers return `GeoResult`.

**Rate limit handling:** if ip-api returns 429, wait and retry with exponential backoff (max 3 retries). Log a warning and continue with `geo=None` for unresolved IPs rather than aborting the scan.

### Gmail Integration (`gmail_client.py`)

**OAuth setup:**
1. User creates a Google Cloud project and enables Gmail API
2. Downloads OAuth client credentials as `credentials.json`
3. Places it at `~/.email-intel/credentials.json` (or sets `GMAIL_CREDENTIALS_PATH`)
4. First run of any Gmail command triggers browser-based OAuth consent flow (redirect URI: `http://localhost:8080`)
5. Refresh token cached at `~/.email-intel/gmail_token.json`

**Scope:** `gmail.readonly` — read-only access, no send/modify.

**Fetching:** `users.messages.get(format='metadata')` for headers only. Supports filtering via `--days`, `--from`, `--query` (passes through to Gmail search syntax). Bulk scan defaults to `--limit 500`; use `--limit 0` for unlimited.

**Errors:** 401/403 → prompt user to re-auth (`email-intel auth`). 429 → exponential backoff, max 3 retries.

### Apple Mail Integration (`apple_mail.py`)

- Walks `~/Library/Mail/V*/` directories to find `.emlx` files (supports V9, V10+)
- Parses `.emlx` format: first line is **byte count** of the RFC 822 message body, followed by the message, followed by a plist trailer. `.emlxpart` attachments are ignored (headers only).
- Filters: `--days` (from file mtime), `--from` (substring match on From header, case-insensitive), `--query` (substring match across all header values, case-insensitive)
- Corrupt/truncated `.emlx` files are logged and skipped, not fatal
- No auth needed — local file reads only

### Reporting (`reporter.py`)

**Single email (`analyze` mode):**

- Origin block: IP, geolocation, ISP/org
- Client identification
- Auth results (SPF/DKIM/DMARC)
- Server hop chain with timestamps and latency
- Flags: Reply-To mismatch, auth failures, unusual origins

**Bulk scan (`scan` mode):**

- Summary table: top sender locations, timezone distribution, client breakdown
- Flagged messages list
- Progress bar during scanning

**Export:** `--format json|csv` with `-o` output path.

### Client Fingerprinting

Best-effort identification via (in priority order):
1. `X-Mailer` header (e.g., `Apple Mail`, `Microsoft Outlook 16.0`)
2. `User-Agent` header (e.g., `Thunderbird 115.0`)
3. `Message-ID` domain lookup table: `@mail.gmail.com` → Gmail, `@outlook.com` → Outlook, `@yahoo.com` → Yahoo Mail, etc.
4. MIME boundary pattern heuristics (fallback, marked as "inferred")

Unknown clients are reported as `Unknown` — no guessing.

## Error Handling

**General principle:** a single bad email never aborts a scan. Errors are logged and the email is skipped with a warning in the output.

- **Malformed headers** (missing Date, no Received, garbled encoding) → parse what's available, set missing fields to `None`, add flag
- **Network unavailable** → geo lookups return `None`, warning logged
- **SQLite cache locked** → skip cache, query provider directly
- **Gmail token expired** → prompt re-auth with `email-intel auth`
- **Empty inbox / no results** → clean message, exit 0

## Configuration

Optional `~/.email-intel/config.toml`:

```toml
[geo]
provider = "ip-api"           # or "maxmind"
maxmind_db_path = ""          # path to .mmdb file

[gmail]
credentials_path = ""         # default: ~/.email-intel/credentials.json

[defaults]
days = 30
limit = 500
format = "table"              # table, json, csv
```

All config values can be overridden by CLI flags or env vars.

## CLI Interface

```bash
# Single email — paste headers interactively (or pipe via stdin)
email-intel analyze

# Single email — Gmail message ID
email-intel analyze --gmail-id 18abc123def

# Single email — .emlx file
email-intel analyze --file ~/Library/Mail/.../message.emlx

# Single email — pipe from stdin
cat headers.txt | email-intel analyze

# Bulk scan — Gmail, last 30 days
email-intel scan --source gmail --days 30

# Bulk scan — Apple Mail, last 30 days
email-intel scan --source apple-mail --days 30

# Bulk scan with limit
email-intel scan --source gmail --days 90 --limit 200

# Export
email-intel scan --source gmail --days 7 --format csv -o report.csv

# Re-authenticate Gmail
email-intel auth

# Version
email-intel --version
```

## Data Flow

1. **Input** → raw headers (paste), Gmail API (message ID or bulk query), or .emlx file(s)
2. **Parse** → extract structured metadata from RFC 822 headers
3. **Geolocate** → resolve originating IPs to locations (cache-first)
4. **Report** → render to terminal, or export to JSON/CSV

## Future (Dashboard Phase)

Not in scope for CLI, but designed with this in mind:

- Web UI with map visualization of sender locations
- Timeline charts of communication patterns
- Sender profiles aggregated over time
- Scheduled inbox scans with change detection
