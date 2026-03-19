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

Private/internal IPs (10.x, 192.168.x, Google/Microsoft internal hops) are labeled but skipped for geolocation.

### Geolocation (`geo.py`)

Two providers behind a common interface:

- **ip-api.com (default)** — `GET http://ip-api.com/json/{ip}`. No API key needed. Rate limited to 45 req/min; bulk scans batch with 1s delays.
- **MaxMind GeoLite2 (optional)** — set `MAXMIND_DB_PATH` env var pointing to local `.mmdb` file. Instant lookups, no rate limits. Falls back to ip-api if not configured.

**Caching:** SQLite cache at `~/.email-intel/geo_cache.db`. 30-day TTL. Both providers return: `GeoResult(ip, city, region, country, lat, lon, isp, org, source)`.

### Gmail Integration (`gmail_client.py`)

- OAuth2 via `google-auth-oauthlib` — first run opens browser for consent
- Token cached at `~/.email-intel/gmail_token.json`
- Scope: `gmail.readonly`
- Fetches headers via `users.messages.get(format='metadata')`
- Supports filtering: `--days`, `--from`, `--query`

### Apple Mail Integration (`apple_mail.py`)

- Walks `~/Library/Mail/V*/` directories to find `.emlx` files
- Parses `.emlx` format: line count prefix + RFC 822 message + plist trailer
- Same filters: `--days`, `--from`, `--query` (searches headers)
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

## CLI Interface

```bash
# Single email — paste headers interactively
email-intel analyze

# Single email — Gmail message ID
email-intel analyze --gmail-id 18abc123def

# Single email — .emlx file
email-intel analyze --file ~/Library/Mail/.../message.emlx

# Bulk scan — Gmail, last 30 days
email-intel scan --source gmail --days 30

# Bulk scan — Apple Mail, last 30 days
email-intel scan --source apple-mail --days 30

# Export
email-intel scan --source gmail --days 7 --format csv -o report.csv
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
