# Email Intel Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local web dashboard at localhost:8888 for browsing org infrastructure profiles and monitoring change intelligence.

**Architecture:** Python HTTP server (`dashboard.py`) serves a single HTML page and 4 JSON API endpoints. Reads from existing SQLite via `OrgStore`. No framework, no build step.

**Tech Stack:** Python stdlib (`http.server`, `json`, `urllib.parse`), vanilla JS, Chart.js CDN, existing `org_store.py`

**Spec:** `docs/superpowers/specs/2026-03-20-dashboard-design.md`

---

## File Structure

```
email_intel/
├── dashboard.py         # CREATE: HTTP server + JSON API (4 endpoints)
├── dashboard.html       # CREATE: Single-page HTML with embedded CSS/JS
├── cli.py               # MODIFY: add 'dashboard' command
├── org_store.py         # MODIFY: add get_changes_with_classification() helper
tests/
├── test_dashboard.py    # CREATE: API endpoint tests
```

---

### Task 1: Add get_changes_with_classification to OrgStore + Dashboard API Server

**Files:**
- Modify: `email_intel/org_store.py`
- Create: `email_intel/dashboard.py`
- Create: `tests/test_dashboard.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_dashboard.py
import json
import threading
import time
from datetime import datetime, timezone
from http.client import HTTPConnection
from email_intel.org_store import OrgStore
from email_intel.models import InfraStack
from email_intel.dashboard import create_server


def _make_stack(**overrides) -> InfraStack:
    defaults = dict(
        mta_vendor="Microsoft Exchange", mta_version="15.2.2562.37",
        email_platform="m365", security_gateway="Proofpoint",
        security_gateway_version="Hydra:6.1.51",
        tls_version="TLS1_2", tls_cipher="AES256",
        dmarc_policy="reject", spf_result="pass",
        dkim_domains=["gs.com"], dlp_system="Titus",
        dlp_metadata={"Aud": "UNR"}, tenant_id="abc-123",
        antispam_scores={"BCL": 0}, proofpoint_engines={"Hydra": "6.1.51"},
        observed_at=datetime(2026, 3, 19, 16, 0, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return InfraStack(**defaults)


class TestDashboardAPI:
    """Integration tests that start a real HTTP server on a random port."""

    @classmethod
    def setup_class(cls):
        import tempfile
        cls.tmp_dir = tempfile.mkdtemp()
        db_path = f"{cls.tmp_dir}/test.db"
        cls.store = OrgStore(db_path=db_path)

        # Seed data
        cls.store.upsert("gs.com", _make_stack())
        cls.store.upsert("google.com", _make_stack(
            mta_vendor="Google", email_platform="google-workspace",
            security_gateway=None, security_gateway_version=None,
            dmarc_policy="reject", dlp_system=None,
        ))
        # Create a change
        stack2 = _make_stack(dmarc_policy="quarantine")
        cls.store.upsert("gs.com", stack2)
        changes = cls.store.get_changes(domain="gs.com")
        if changes:
            cls.store.classify_change(changes[0].id, "negative", 0.9, "DMARC weakened", "security")

        cls.store.set_entity_mapping("gs.com", "Goldman Sachs", sector="Finance")

        cls.server = create_server(cls.store, port=0)  # port=0 → random available port
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def teardown_class(cls):
        cls.server.shutdown()

    def _get(self, path: str) -> tuple[int, dict | list]:
        conn = HTTPConnection("localhost", self.port)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = json.loads(resp.read().decode())
        conn.close()
        return resp.status, body

    def test_api_orgs(self):
        status, data = self._get("/api/orgs")
        assert status == 200
        assert len(data) == 2
        domains = {d["domain"] for d in data}
        assert "gs.com" in domains
        assert "google.com" in domains
        gs = next(d for d in data if d["domain"] == "gs.com")
        assert gs["stack"]["mta_vendor"] == "Microsoft Exchange"

    def test_api_orgs_detail(self):
        status, data = self._get("/api/orgs/gs.com")
        assert status == 200
        assert data["profile"]["domain"] == "gs.com"
        assert len(data["changes"]) >= 1
        assert data["entity"]["entity_name"] == "Goldman Sachs"

    def test_api_orgs_detail_unknown(self):
        status, data = self._get("/api/orgs/unknown.example.com")
        assert status == 404

    def test_api_changes(self):
        status, data = self._get("/api/changes")
        assert status == 200
        assert len(data) >= 1
        # Check classification fields are present
        change = data[0]
        assert "signal" in change
        assert "reasoning" in change

    def test_api_changes_filtered(self):
        status, data = self._get("/api/changes?signal=negative")
        assert status == 200
        for c in data:
            assert c["signal"] == "negative"

    def test_api_stats(self):
        status, data = self._get("/api/stats")
        assert status == 200
        assert data["total_orgs"] == 2
        assert "platform_breakdown" in data
        assert "dmarc_breakdown" in data

    def test_root_returns_html(self):
        conn = HTTPConnection("localhost", self.port)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        assert resp.status == 200
        assert "<!DOCTYPE html>" in body

    def test_404_unknown_path(self):
        status, data = self._get("/api/unknown")
        assert status == 404
```

- [ ] **Step 2: Run to verify fail**

Run: `python3 -m pytest tests/test_dashboard.py -v`
Expected: FAIL — `ModuleNotFoundError: cannot import name 'create_server' from 'email_intel.dashboard'`

- [ ] **Step 3: Add `get_changes_with_classification()` to `org_store.py`**

Add this method to the `OrgStore` class, after `get_changes()`:

```python
    def get_changes_with_classification(
        self, domain: str | None = None, days: int | None = None, signal: str | None = None,
    ) -> list[dict]:
        """Like get_changes but returns dicts with classification fields included."""
        conn = self._conn()
        query = "SELECT sc.*, op.display_name FROM stack_changes sc LEFT JOIN org_profiles op ON sc.domain = op.domain WHERE 1=1"
        params: list = []
        if domain:
            query += " AND sc.domain = ?"
            params.append(domain)
        if days:
            cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=days)).isoformat()
            query += " AND sc.timestamp >= ?"
            params.append(cutoff)
        if signal:
            query += " AND sc.signal = ?"
            params.append(signal)
        query += " ORDER BY sc.timestamp DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [
            {
                "id": r["id"], "domain": r["domain"],
                "display_name": r["display_name"] or r["domain"],
                "timestamp": r["timestamp"], "field": r["field"],
                "old_value": r["old_value"], "new_value": r["new_value"],
                "signal": r["signal"], "confidence": r["confidence"],
                "reasoning": r["reasoning"], "category": r["category"],
            }
            for r in rows
        ]
```

- [ ] **Step 4: Write `email_intel/dashboard.py`**

```python
from __future__ import annotations
import json
import logging
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from email_intel.org_store import OrgStore

logger = logging.getLogger(__name__)

_HTML_PATH = Path(__file__).parent / "dashboard.html"


def _profile_to_dict(profile) -> dict:
    s = profile.current_stack
    return {
        "domain": profile.domain,
        "display_name": profile.display_name or profile.domain,
        "entity_id": profile.entity_id,
        "sector": profile.sector,
        "entity_source": profile.entity_source,
        "first_seen": profile.first_seen.isoformat(),
        "last_seen": profile.last_seen.isoformat(),
        "email_count": profile.email_count,
        "stack": {
            "mta_vendor": s.mta_vendor,
            "mta_version": s.mta_version,
            "email_platform": s.email_platform,
            "security_gateway": s.security_gateway,
            "security_gateway_version": s.security_gateway_version,
            "tls_version": s.tls_version,
            "tls_cipher": s.tls_cipher,
            "dmarc_policy": s.dmarc_policy,
            "spf_result": s.spf_result,
            "dkim_domains": s.dkim_domains,
            "dlp_system": s.dlp_system,
            "tenant_id": s.tenant_id,
        },
    }


class DashboardHandler(BaseHTTPRequestHandler):
    store: OrgStore  # set on the class before serving

    def log_message(self, format, *args):
        logger.debug(format, *args)

    def _json_response(self, data, status=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html_response(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, message):
        self._json_response({"error": message}, status)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)

        try:
            if path == "/":
                self._handle_root()
            elif path == "/api/orgs":
                self._handle_orgs()
            elif path.startswith("/api/orgs/"):
                domain = path[len("/api/orgs/"):]
                self._handle_org_detail(domain)
            elif path == "/api/changes":
                self._handle_changes(params)
            elif path == "/api/stats":
                self._handle_stats()
            else:
                self._error(404, "Not found")
        except Exception as e:
            logger.error("Server error: %s", e)
            self._error(500, str(e))

    def _handle_root(self):
        if _HTML_PATH.exists():
            html = _HTML_PATH.read_text(encoding="utf-8")
        else:
            html = "<html><body><h1>dashboard.html not found</h1></body></html>"
        self._html_response(html)

    def _handle_orgs(self):
        profiles = self.store.list_profiles()
        self._json_response([_profile_to_dict(p) for p in profiles])

    def _handle_org_detail(self, domain: str):
        profile = self.store.get_profile(domain)
        entity = self.store.resolve_entity(domain)
        if not profile and not entity:
            self._error(404, f"No profile found for {domain}")
            return

        changes = self.store.get_changes_with_classification(domain=domain)

        self._json_response({
            "profile": _profile_to_dict(profile) if profile else None,
            "changes": changes,
            "entity": {
                "entity_name": entity.entity_name,
                "sector": entity.sector,
                "source": entity.source,
            } if entity else None,
        })

    def _handle_changes(self, params: dict):
        days = int(params.get("days", [0])[0]) or None
        signal = params.get("signal", [None])[0]
        domain = params.get("domain", [None])[0]
        changes = self.store.get_changes_with_classification(
            domain=domain, days=days, signal=signal,
        )
        self._json_response(changes)

    def _handle_stats(self):
        profiles = self.store.list_profiles()
        platform_counter: Counter[str] = Counter()
        gateway_counter: Counter[str] = Counter()
        dmarc_counter: Counter[str] = Counter()
        last_seen = None

        for p in profiles:
            s = p.current_stack
            platform_counter[s.email_platform or "other"] += 1
            if s.security_gateway:
                gateway_counter[s.security_gateway] += 1
            dmarc_counter[s.dmarc_policy or "unknown"] += 1
            if last_seen is None or p.last_seen > last_seen:
                last_seen = p.last_seen

        all_changes = self.store.get_changes_with_classification()
        changes_7d = self.store.get_changes_with_classification(days=7)

        self._json_response({
            "total_orgs": len(profiles),
            "platform_breakdown": dict(platform_counter),
            "security_gateways": dict(gateway_counter),
            "dmarc_breakdown": dict(dmarc_counter),
            "total_changes": len(all_changes),
            "changes_7d": len(changes_7d),
            "last_scan": last_seen.isoformat() if last_seen else None,
        })


def create_server(store: OrgStore, port: int = 8888) -> HTTPServer:
    DashboardHandler.store = store
    server = HTTPServer(("localhost", port), DashboardHandler)
    return server
```

- [ ] **Step 5: Run tests and verify pass**

Run: `python3 -m pytest tests/test_dashboard.py -v`
Expected: All 8 tests PASS

- [ ] **Step 6: Commit**

```bash
git add email_intel/dashboard.py email_intel/org_store.py tests/test_dashboard.py
git commit -m "feat: dashboard API server — 4 JSON endpoints + get_changes_with_classification"
```

---

### Task 2: Dashboard HTML — Single Page with Embedded CSS/JS

**Files:**
- Create: `email_intel/dashboard.html`

This is the entire frontend in one HTML file. Embedded CSS for dark theme, embedded JS for fetching data and rendering tables.

- [ ] **Step 1: Write `email_intel/dashboard.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Email Intel — Org Intelligence Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #1a1a2e; color: #e0e0e0;
    font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 13px; line-height: 1.5;
  }
  a { color: #00d26a; text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* Header */
  .header {
    padding: 20px 24px 12px; border-bottom: 1px solid #2a2a4a;
    display: flex; justify-content: space-between; align-items: flex-end;
  }
  .header h1 { font-size: 20px; color: #fff; font-weight: 600; }
  .header .subtitle { font-size: 12px; color: #888; margin-top: 2px; }
  .stats-strip {
    display: flex; gap: 24px; font-size: 12px; color: #aaa;
  }
  .stats-strip .stat-val { color: #fff; font-weight: 600; }

  /* Search + Filters */
  .controls {
    padding: 12px 24px; display: flex; gap: 12px; align-items: center;
    border-bottom: 1px solid #2a2a4a;
  }
  input[type="text"] {
    background: #16213e; border: 1px solid #2a2a4a; color: #e0e0e0;
    padding: 6px 12px; border-radius: 4px; font-family: inherit; font-size: 12px;
    width: 300px;
  }
  input[type="text"]::placeholder { color: #555; }
  input[type="text"]:focus { outline: none; border-color: #00d26a; }
  select {
    background: #16213e; border: 1px solid #2a2a4a; color: #e0e0e0;
    padding: 6px 8px; border-radius: 4px; font-family: inherit; font-size: 12px;
  }

  /* Tables */
  .panel { padding: 0 24px 24px; }
  .panel h2 { font-size: 14px; color: #aaa; padding: 16px 0 8px; text-transform: uppercase; letter-spacing: 1px; }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left; padding: 8px 12px; color: #888; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.5px; cursor: pointer;
    border-bottom: 1px solid #2a2a4a; user-select: none;
  }
  th:hover { color: #00d26a; }
  th .sort-arrow { font-size: 10px; margin-left: 4px; }
  td { padding: 8px 12px; border-bottom: 1px solid #1e1e3a; }
  tr:hover td { background: #16213e; }
  tr:nth-child(even) td { background: #1e1e38; }
  tr:nth-child(even):hover td { background: #16213e; }
  .clickable { cursor: pointer; }

  /* DMARC badges */
  .badge { padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; }
  .badge-green { background: #0a3d1f; color: #00d26a; }
  .badge-yellow { background: #3d3a0a; color: #f5c842; }
  .badge-red { background: #3d0a1a; color: #f92672; }
  .badge-gray { background: #2a2a3a; color: #888; }

  /* Signal badges */
  .signal-positive { color: #00d26a; }
  .signal-negative { color: #f92672; }
  .signal-neutral { color: #888; }
  .category-tag {
    font-size: 10px; padding: 1px 6px; border-radius: 2px;
    background: #2a2a4a; color: #aaa; margin-left: 8px;
  }

  /* Detail panel (inline expand) */
  .detail-row td { background: #16213e !important; padding: 16px 24px; }
  .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .detail-section h3 { font-size: 12px; color: #00d26a; margin-bottom: 8px; text-transform: uppercase; }
  .detail-field { display: flex; justify-content: space-between; padding: 3px 0; }
  .detail-field .label { color: #888; }
  .detail-field .value { color: #e0e0e0; text-align: right; }
  .detail-changes { margin-top: 12px; }
  .detail-changes .change-item { padding: 4px 0; font-size: 12px; }

  /* Change feed */
  .change-entry {
    padding: 10px 0; border-bottom: 1px solid #1e1e3a;
    display: grid; grid-template-columns: 100px 160px 1fr auto; gap: 12px; align-items: center;
  }
  .change-entry .timestamp { color: #666; font-size: 11px; }
  .change-entry .org { color: #fff; }
  .change-entry .detail { color: #aaa; }
  .change-entry .signal-badge { text-align: right; }

  /* Filter tabs */
  .filter-tabs { display: flex; gap: 0; margin-bottom: 12px; }
  .filter-tab {
    padding: 6px 16px; background: #16213e; border: 1px solid #2a2a4a;
    color: #888; cursor: pointer; font-family: inherit; font-size: 12px;
  }
  .filter-tab:first-child { border-radius: 4px 0 0 4px; }
  .filter-tab:last-child { border-radius: 0 4px 4px 0; }
  .filter-tab.active { background: #2a2a4a; color: #00d26a; border-color: #00d26a; }

  /* Chart container */
  .charts { display: flex; gap: 24px; padding: 0 24px 16px; }
  .chart-box { width: 200px; height: 200px; }

  /* Empty state */
  .empty { text-align: center; padding: 48px; color: #555; font-size: 14px; }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>Email Intel</h1>
    <div class="subtitle">Org Intelligence Dashboard</div>
  </div>
  <div class="stats-strip" id="stats-strip">Loading...</div>
</div>

<div class="charts">
  <div class="chart-box"><canvas id="platformChart"></canvas></div>
  <div class="chart-box"><canvas id="dmarcChart"></canvas></div>
</div>

<div class="controls">
  <input type="text" id="search" placeholder="Search orgs..." oninput="filterOrgs()">
  <select id="platformFilter" onchange="filterOrgs()">
    <option value="">All Platforms</option>
    <option value="m365">M365</option>
    <option value="google-workspace">Google Workspace</option>
    <option value="other">Other</option>
  </select>
  <select id="dmarcFilter" onchange="filterOrgs()">
    <option value="">All DMARC</option>
    <option value="reject">Reject</option>
    <option value="quarantine">Quarantine</option>
    <option value="none">None</option>
  </select>
</div>

<div class="panel">
  <h2>Organizations (<span id="org-count">0</span>)</h2>
  <table id="org-table">
    <thead>
      <tr>
        <th onclick="sortOrgs('domain')">Domain <span class="sort-arrow"></span></th>
        <th onclick="sortOrgs('display_name')">Name</th>
        <th onclick="sortOrgs('email_platform')">Platform</th>
        <th onclick="sortOrgs('security_gateway')">Security</th>
        <th onclick="sortOrgs('dmarc_policy')">DMARC</th>
        <th onclick="sortOrgs('tls_version')">TLS</th>
        <th onclick="sortOrgs('dlp_system')">DLP</th>
        <th onclick="sortOrgs('email_count')">Emails</th>
        <th onclick="sortOrgs('last_seen')">Last Seen</th>
      </tr>
    </thead>
    <tbody id="org-tbody"></tbody>
  </table>
</div>

<div class="panel">
  <h2>Change Feed (<span id="change-count">0</span>)</h2>
  <div style="display:flex;gap:12px;align-items:center;margin-bottom:12px;">
    <div class="filter-tabs">
      <button class="filter-tab active" onclick="filterChanges('all',this)">All</button>
      <button class="filter-tab" onclick="filterChanges('positive',this)">Positive</button>
      <button class="filter-tab" onclick="filterChanges('negative',this)">Negative</button>
      <button class="filter-tab" onclick="filterChanges('neutral',this)">Neutral</button>
    </div>
    <select id="changeDays" onchange="loadChanges()">
      <option value="">All Time</option>
      <option value="7">Last 7 Days</option>
      <option value="30" selected>Last 30 Days</option>
      <option value="90">Last 90 Days</option>
    </select>
  </div>
  <div id="change-feed"></div>
</div>

<script>
let allOrgs = [];
let allChanges = [];
let sortField = 'email_count';
let sortAsc = false;
let expandedDomain = null;
let changeSignalFilter = 'all';

// ---- Data Loading ----
async function loadAll() {
  const [orgs, changes, stats] = await Promise.all([
    fetch('/api/orgs').then(r => r.json()),
    fetch('/api/changes?days=30').then(r => r.json()),
    fetch('/api/stats').then(r => r.json()),
  ]);
  allOrgs = orgs;
  allChanges = changes;
  renderStats(stats);
  renderCharts(stats);
  renderOrgs();
  renderChanges();
}

// ---- Stats ----
function renderStats(stats) {
  const strip = document.getElementById('stats-strip');
  const gw = Object.values(stats.security_gateways || {}).reduce((a,b) => a+b, 0);
  const rejectCount = stats.dmarc_breakdown?.reject || 0;
  strip.innerHTML = `
    <span><span class="stat-val">${stats.total_orgs}</span> orgs</span>
    <span><span class="stat-val">${gw}</span> with security gateway</span>
    <span><span class="stat-val">${rejectCount}</span> DMARC reject</span>
    <span><span class="stat-val">${stats.changes_7d}</span> changes this week</span>
    <span>Last scan: ${stats.last_scan ? stats.last_scan.split('T')[0] : 'never'}</span>
  `;
}

// ---- Charts ----
function renderCharts(stats) {
  const platformCtx = document.getElementById('platformChart');
  new Chart(platformCtx, {
    type: 'doughnut',
    data: {
      labels: Object.keys(stats.platform_breakdown || {}),
      datasets: [{
        data: Object.values(stats.platform_breakdown || {}),
        backgroundColor: ['#0e4d92', '#00d26a', '#f5c842', '#f92672', '#888'],
      }]
    },
    options: {
      plugins: { legend: { display: true, position: 'bottom', labels: { color: '#888', font: { size: 10 } } },
        title: { display: true, text: 'Platforms', color: '#aaa', font: { size: 11 } } },
      responsive: true, maintainAspectRatio: true,
    }
  });
  const dmarcCtx = document.getElementById('dmarcChart');
  new Chart(dmarcCtx, {
    type: 'doughnut',
    data: {
      labels: Object.keys(stats.dmarc_breakdown || {}),
      datasets: [{
        data: Object.values(stats.dmarc_breakdown || {}),
        backgroundColor: ['#00d26a', '#f5c842', '#f92672', '#888', '#555'],
      }]
    },
    options: {
      plugins: { legend: { display: true, position: 'bottom', labels: { color: '#888', font: { size: 10 } } },
        title: { display: true, text: 'DMARC Policy', color: '#aaa', font: { size: 11 } } },
      responsive: true, maintainAspectRatio: true,
    }
  });
}

// ---- Org Table ----
function dmarcBadge(policy) {
  if (policy === 'reject') return '<span class="badge badge-green">reject</span>';
  if (policy === 'quarantine') return '<span class="badge badge-yellow">quarantine</span>';
  if (policy === 'none') return '<span class="badge badge-red">none</span>';
  return '<span class="badge badge-gray">?</span>';
}

function renderOrgs() {
  const search = document.getElementById('search').value.toLowerCase();
  const platformF = document.getElementById('platformFilter').value;
  const dmarcF = document.getElementById('dmarcFilter').value;

  let filtered = allOrgs.filter(o => {
    if (search && !o.domain.includes(search) && !(o.display_name || '').toLowerCase().includes(search)) return false;
    if (platformF && o.stack.email_platform !== platformF) return false;
    if (dmarcF && o.stack.dmarc_policy !== dmarcF) return false;
    return true;
  });

  filtered.sort((a, b) => {
    let va = sortField === 'email_count' ? a.email_count :
             sortField === 'last_seen' ? a.last_seen :
             sortField.includes('.') ? a.stack[sortField.split('.')[1]] :
             (sortField === 'email_platform' || sortField === 'security_gateway' || sortField === 'dmarc_policy' || sortField === 'tls_version' || sortField === 'dlp_system')
               ? (a.stack[sortField] || '') : (a[sortField] || '');
    let vb = sortField === 'email_count' ? b.email_count :
             sortField === 'last_seen' ? b.last_seen :
             sortField.includes('.') ? b.stack[sortField.split('.')[1]] :
             (sortField === 'email_platform' || sortField === 'security_gateway' || sortField === 'dmarc_policy' || sortField === 'tls_version' || sortField === 'dlp_system')
               ? (b.stack[sortField] || '') : (b[sortField] || '');
    if (typeof va === 'number') return sortAsc ? va - vb : vb - va;
    return sortAsc ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
  });

  document.getElementById('org-count').textContent = filtered.length;
  const tbody = document.getElementById('org-tbody');
  tbody.innerHTML = '';

  filtered.forEach(o => {
    const s = o.stack;
    const tr = document.createElement('tr');
    tr.className = 'clickable';
    tr.onclick = () => toggleDetail(o.domain, tr);
    tr.innerHTML = `
      <td>${o.domain}</td>
      <td>${o.display_name || o.domain}</td>
      <td>${s.email_platform || '?'}</td>
      <td>${s.security_gateway || '-'}</td>
      <td>${dmarcBadge(s.dmarc_policy)}</td>
      <td>${s.tls_version || '?'}</td>
      <td>${s.dlp_system || '-'}</td>
      <td>${o.email_count}</td>
      <td>${o.last_seen ? o.last_seen.split('T')[0] : '?'}</td>
    `;
    tbody.appendChild(tr);

    if (expandedDomain === o.domain) {
      const detailTr = document.createElement('tr');
      detailTr.className = 'detail-row';
      detailTr.innerHTML = `<td colspan="9"><div id="detail-${o.domain}">Loading...</div></td>`;
      tbody.appendChild(detailTr);
      loadDetail(o.domain);
    }
  });
}

async function toggleDetail(domain, tr) {
  if (expandedDomain === domain) { expandedDomain = null; renderOrgs(); return; }
  expandedDomain = domain;
  renderOrgs();
}

async function loadDetail(domain) {
  const data = await fetch(`/api/orgs/${domain}`).then(r => r.json());
  const el = document.getElementById(`detail-${domain}`);
  if (!el) return;
  const p = data.profile;
  const s = p ? p.stack : {};
  const entity = data.entity;

  let html = '<div class="detail-grid"><div class="detail-section"><h3>Infrastructure Stack</h3>';
  const fields = [
    ['MTA', `${s.mta_vendor || '?'} ${s.mta_version || ''}`],
    ['Platform', s.email_platform || '?'],
    ['Security', `${s.security_gateway || '-'} ${s.security_gateway_version || ''}`],
    ['TLS', `${s.tls_version || '?'} / ${s.tls_cipher || '?'}`],
    ['DMARC', s.dmarc_policy || '?'],
    ['DLP', s.dlp_system || '-'],
    ['Tenant ID', s.tenant_id || '-'],
    ['DKIM', (s.dkim_domains || []).join(', ') || '-'],
  ];
  fields.forEach(([l, v]) => { html += `<div class="detail-field"><span class="label">${l}</span><span class="value">${v}</span></div>`; });
  html += '</div><div class="detail-section">';
  if (entity) {
    html += `<h3>Entity</h3>
      <div class="detail-field"><span class="label">Name</span><span class="value">${entity.entity_name}</span></div>
      <div class="detail-field"><span class="label">Sector</span><span class="value">${entity.sector || '-'}</span></div>
      <div class="detail-field"><span class="label">Source</span><span class="value">${entity.source}</span></div>`;
  }
  if (p) {
    html += `<h3 style="margin-top:12px">Stats</h3>
      <div class="detail-field"><span class="label">Emails</span><span class="value">${p.email_count}</span></div>
      <div class="detail-field"><span class="label">First Seen</span><span class="value">${p.first_seen.split('T')[0]}</span></div>
      <div class="detail-field"><span class="label">Last Seen</span><span class="value">${p.last_seen.split('T')[0]}</span></div>`;
  }
  html += '</div></div>';

  if (data.changes && data.changes.length > 0) {
    html += '<div class="detail-changes"><h3>Change History</h3>';
    data.changes.forEach(c => {
      const cls = c.signal ? `signal-${c.signal}` : '';
      html += `<div class="change-item">
        <span style="color:#666">${(c.timestamp||'').split('T')[0]}</span>
        <span class="${cls}"> ${c.field}: ${c.old_value || '-'} → ${c.new_value || '-'}</span>
        ${c.reasoning ? `<span style="color:#555"> — ${c.reasoning}</span>` : ''}
      </div>`;
    });
    html += '</div>';
  }
  el.innerHTML = html;
}

function sortOrgs(field) {
  if (sortField === field) { sortAsc = !sortAsc; } else { sortField = field; sortAsc = true; }
  renderOrgs();
}
function filterOrgs() { renderOrgs(); }

// ---- Change Feed ----
function renderChanges() {
  let filtered = allChanges;
  if (changeSignalFilter !== 'all') {
    filtered = filtered.filter(c => c.signal === changeSignalFilter);
  }
  document.getElementById('change-count').textContent = filtered.length;
  const feed = document.getElementById('change-feed');
  if (filtered.length === 0) {
    feed.innerHTML = '<div class="empty">No changes found.</div>';
    return;
  }
  feed.innerHTML = filtered.slice(0, 100).map(c => `
    <div class="change-entry">
      <span class="timestamp">${(c.timestamp||'').split('T')[0]}</span>
      <span class="org">${c.display_name || c.domain}</span>
      <span class="detail">${c.field}: ${c.old_value || '-'} → ${c.new_value || '-'}</span>
      <span class="signal-badge">
        <span class="signal-${c.signal || 'neutral'}">${c.signal || '?'}</span>
        ${c.category ? `<span class="category-tag">${c.category}</span>` : ''}
      </span>
    </div>
  `).join('');
}

async function loadChanges() {
  const days = document.getElementById('changeDays').value;
  const url = days ? `/api/changes?days=${days}` : '/api/changes';
  allChanges = await fetch(url).then(r => r.json());
  renderChanges();
}

function filterChanges(signal, btn) {
  changeSignalFilter = signal;
  document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  renderChanges();
}

// ---- Init ----
loadAll();
</script>
</body>
</html>
```

- [ ] **Step 2: Verify HTML is served by running tests**

Run: `python3 -m pytest tests/test_dashboard.py::TestDashboardAPI::test_root_returns_html -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add email_intel/dashboard.html
git commit -m "feat: dashboard HTML — dark theme, org table, change feed, charts"
```

---

### Task 3: CLI Dashboard Command

**Files:**
- Modify: `email_intel/cli.py`

- [ ] **Step 1: Add dashboard command to `email_intel/cli.py`**

Add after the `changes` command:

```python
@main.command()
@click.option("--port", type=int, default=8888, help="Server port")
@click.option("--no-open", is_flag=True, help="Don't open browser")
def dashboard(port, no_open):
    """Launch the org intelligence dashboard in your browser."""
    cfg = load_config()
    from email_intel.dashboard import create_server
    from email_intel.org_store import OrgStore as _OrgStore

    store = _OrgStore(db_path=cfg.orgs_db_path)

    try:
        server = create_server(store, port=port)
    except OSError as e:
        if "Address already in use" in str(e) or "address already in use" in str(e):
            console.print(f"[red]Port {port} already in use. Try --port {port + 1}[/red]")
            sys.exit(1)
        raise

    url = f"http://localhost:{port}"
    console.print(f"Dashboard running at [bold]{url}[/bold] (Ctrl+C to stop)")

    if not no_open:
        import webbrowser
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\nShutting down...")
        server.shutdown()
```

- [ ] **Step 2: Test manually**

```bash
PYTHONPATH=/Users/jamest/email-intel python3 -c "
import sys; sys.argv = ['email-intel', 'dashboard', '--no-open']
from email_intel.cli import main; main(standalone_mode=False)
" &
sleep 2
curl -s http://localhost:8888/api/stats | python3 -m json.tool
curl -s http://localhost:8888/api/orgs | python3 -m json.tool | head -20
kill %1
```

- [ ] **Step 3: Run full test suite**

Run: `python3 -m pytest tests/ -v --tb=short`
Expected: All tests PASS (97 existing + 8 new dashboard = 105)

- [ ] **Step 4: Commit**

```bash
git add email_intel/cli.py
git commit -m "feat: CLI dashboard command — launches local web UI on localhost:8888"
```

- [ ] **Step 5: Push**

```bash
git push origin main
```
