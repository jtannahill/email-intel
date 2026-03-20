# Email Intel Dashboard — Design Spec

## Overview

Local-only web dashboard at `localhost:8888` for viewing org infrastructure profiles and change intelligence. Single Python server, one HTML page with embedded JS/CSS, reads from existing SQLite database. No build step, no framework, no npm.

## Goals

- Browse all 147+ org profiles in a sortable/filterable table
- Click into any org for full infrastructure stack + change history
- Monitor a reverse-chronological change feed with signal classification
- Summary stats at a glance (total orgs, platform breakdown, recent changes)

## Architecture

```
Browser (localhost:8888)
  ├── GET /              → HTML dashboard (single page, embedded JS/CSS)
  ├── GET /api/orgs      → JSON list of all org profiles
  ├── GET /api/orgs/:domain → JSON detail for one org (stack + changes + entity)
  ├── GET /api/changes   → JSON change feed (?days=&signal=&domain=)
  └── GET /api/stats     → JSON summary stats

Python (http.server + OrgStore)
  └── Reads from ~/.email-intel/orgs.db
```

### New Files

```
email_intel/
├── dashboard.py         # HTTP server + JSON API endpoints
├── dashboard.html       # Single-page HTML with embedded CSS/JS
└── cli.py               # MODIFY: add 'dashboard' command
```

### Dependencies

- Python stdlib only (`http.server`, `json`, `urllib.parse`)
- Chart.js loaded from CDN (`https://cdn.jsdelivr.net/npm/chart.js`)
- Existing `org_store.py` for all data access

## API Endpoints

### GET /api/orgs

Returns all org profiles as JSON array.

```json
[
  {
    "domain": "gs.com",
    "display_name": "Goldman Sachs",
    "entity_id": "ent_123",
    "sector": "Financial Services",
    "entity_source": "manual",
    "first_seen": "2026-03-20T...",
    "last_seen": "2026-03-20T...",
    "email_count": 3,
    "stack": {
      "mta_vendor": "Microsoft Exchange",
      "mta_version": "15.20.9723.19",
      "email_platform": "m365",
      "security_gateway": "Proofpoint",
      "security_gateway_version": "ICAP:2.0.293, Aquarius:18.0.1143, Hydra:6.1.51",
      "tls_version": "TLS1_2",
      "tls_cipher": "ECDHE",
      "dmarc_policy": "reject",
      "spf_result": "pass",
      "dkim_domains": ["gs.com"],
      "dlp_system": "Titus",
      "tenant_id": "38651f6f-..."
    }
  }
]
```

### GET /api/orgs/:domain

Returns single org detail with stack + change history + entity mapping.

```json
{
  "profile": { ... },
  "changes": [
    {
      "id": 42,
      "timestamp": "2026-03-20T...",
      "field": "dmarc_policy",
      "old_value": "quarantine",
      "new_value": "reject",
      "signal": "positive",
      "confidence": 1.0,
      "reasoning": "DMARC hardened to reject",
      "category": "security"
    }
  ],
  "entity": {
    "entity_name": "Goldman Sachs",
    "sector": "Financial Services",
    "source": "manual"
  }
}
```

### GET /api/changes

Query params: `days` (int), `signal` (positive|negative|neutral), `domain` (str).

Returns array of change objects (same shape as above) with org display_name included.

### GET /api/stats

```json
{
  "total_orgs": 147,
  "platform_breakdown": {"m365": 82, "google-workspace": 55, "other": 10},
  "security_gateways": {"Proofpoint": 5, "Mimecast": 1},
  "dmarc_breakdown": {"reject": 30, "quarantine": 25, "none": 40, "unknown": 52},
  "total_changes": 234,
  "changes_7d": 12,
  "last_scan": "2026-03-20T..."
}
```

## Dashboard Layout

### Header Bar

- Title: "Email Intel" with subtitle "Org Intelligence Dashboard"
- Stats strip: total orgs | orgs with security gateway | DMARC reject count | changes this week
- Last scan timestamp

### Org Table (top panel)

Sortable columns:
- Domain
- Name (from entity map or domain)
- Platform (m365 / google-workspace / other)
- Security Gateway (Proofpoint / Mimecast / - )
- DMARC (reject / quarantine / none / ?)
- TLS
- DLP
- Emails (count)
- Last Seen

Features:
- Search bar filters across domain + name
- Click column headers to sort
- DMARC color coding: reject=green, quarantine=yellow, none/missing=red
- Click row → expands inline detail panel showing full stack, change history, entity info

### Change Feed (bottom panel)

Reverse-chronological list of all detected changes.

Each entry shows:
- Timestamp
- Org name (domain)
- Field changed
- Old → New values
- Signal badge: green "positive", red "negative", gray "neutral"
- Category tag: security, modernization, migration, cost-cut, maintenance
- Reasoning text

Filter controls:
- Signal tabs: All | Positive | Negative | Neutral
- Days dropdown: 7d, 30d, 90d, All
- Domain search

### Styling

- Dark theme (#1a1a2e background, #e0e0e0 text)
- Monospace font (JetBrains Mono or system monospace)
- Accent colors: green (#00d26a) for positive, red (#f92672) for negative, gray (#888) for neutral
- Tables with alternating row colors
- Minimal borders, clean spacing
- Responsive (works on laptop screens)

## Server Implementation

`dashboard.py` subclasses `http.server.BaseHTTPRequestHandler`:

- Routes: parse URL path, dispatch to handler methods
- API handlers: instantiate `OrgStore`, query, serialize to JSON, return with `application/json` content type
- HTML handler: read and serve `dashboard.html`
- CORS: not needed (same origin)
- Error handling: 404 for unknown routes, 500 with JSON error for API failures

Launched via:
```python
server = HTTPServer(("localhost", 8888), DashboardHandler)
server.serve_forever()
```

## CLI Addition

New command on the `main` Click group:

```bash
email-intel dashboard [--port 8888] [--no-open]
```

- Starts the HTTP server
- Opens `http://localhost:8888` in default browser (unless `--no-open`)
- Prints "Dashboard running at http://localhost:8888 (Ctrl+C to stop)"
- Blocks until Ctrl+C

## Error Handling

- Missing `orgs.db` → API returns empty arrays, dashboard shows "No data yet. Run a scan first."
- Malformed query params → ignored, use defaults
- Server errors → JSON `{"error": "..."}` with 500 status
- Large datasets → pagination not needed for v1 (147 orgs fits easily)

## Future (Not in v1 Scope)

- World map with sender geolocations
- Sector aggregation view
- Org timeline charts (stack changes over time)
- Auto-refresh / WebSocket for live updates during scan
- Deploy to CloudFront for multi-device access
