# Org Intelligence Tracker — Design Spec

## Overview

Extension to email-intel that passively builds infrastructure fingerprints for every organization that emails you. Tracks changes over time, classifies them as investment signals (positive/negative/neutral), and bridges to the Plocamium content engine for news correlation and entity momentum scoring.

## Goals

- Profile every org's email infrastructure from inbox headers (MTA, security gateway, TLS, DMARC, DLP, platform)
- Detect and surface changes over time with inline CLI alerts
- Classify changes as positive (investment/modernization), negative (cost-cutting/degradation), or neutral (maintenance)
- Map domains to Plocamium entities for sector-level correlation
- Emit signals for the Plocamium content engine pipeline

## Data Models

### InfraStack

Snapshot of an org's email infrastructure extracted from a single email's headers.

```python
@dataclass
class InfraStack:
    mta_vendor: str | None          # Microsoft Exchange, Google, Postfix, Sendmail
    mta_version: str | None         # 15.2.2562.37
    email_platform: str | None      # m365, google-workspace, on-prem-exchange, other
    security_gateway: str | None    # Proofpoint, Mimecast, Barracuda, Cisco IronPort
    security_gateway_version: str | None  # parsed engine versions string
    tls_version: str | None         # TLS1_2, TLS1_3
    tls_cipher: str | None          # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    dmarc_policy: str | None        # none, quarantine, reject
    spf_result: str | None          # pass, fail, softfail
    dkim_domains: list[str]         # signing domains
    dlp_system: str | None          # Titus, MSIP, Forcepoint, Boldon James
    dlp_metadata: dict              # decoded Titus/MSIP labels
    tenant_id: str | None           # M365 tenant GUID
    antispam_scores: dict           # BCL, SCL, SFS codes
    proofpoint_engines: dict | None # Aquarius, Hydra, FMLib versions
    observed_at: datetime
```

### OrgProfile

Accumulated profile for a domain, stored in SQLite.

```python
@dataclass
class OrgProfile:
    domain: str                     # gs.com
    display_name: str | None        # Goldman Sachs
    entity_id: str | None           # Plocamium entity ID
    sector: str | None              # Financial Services
    entity_source: str              # plocamium, manual, inferred
    first_seen: datetime
    last_seen: datetime
    email_count: int                # total emails observed
    current_stack: InfraStack
```

### StackChange

A single detected change in an org's infrastructure.

```python
@dataclass
class StackChange:
    domain: str
    timestamp: datetime
    field: str                      # e.g. "security_gateway_version"
    old_value: str | None
    new_value: str | None
```

### ChangeClassification

ML/rules classification of a stack change.

```python
@dataclass
class ChangeClassification:
    change: StackChange
    signal: str                     # positive, negative, neutral
    confidence: float               # 0.0-1.0
    reasoning: str                  # "DMARC none→reject = security hardening"
    category: str                   # modernization, security, migration, cost-cut, maintenance
```

### DomainEntityMap

Maps email domains to Plocamium entities.

```python
@dataclass
class DomainEntityMap:
    domain: str                     # gs.com
    entity_id: str | None           # Plocamium entity ID
    entity_name: str                # Goldman Sachs
    sector: str | None              # Financial Services
    source: str                     # plocamium, manual, inferred
```

### OrgInfraSignal

Event emitted to Plocamium content engine.

```python
@dataclass
class OrgInfraSignal:
    domain: str
    entity_id: str | None
    entity_name: str
    sector: str | None
    change: StackChange
    classification: ChangeClassification
    timestamp: datetime
```

## Architecture

### New Modules

```
email_intel/
├── org_profiler.py      # Header → InfraStack extraction, snapshot diffing
├── org_store.py         # SQLite CRUD for OrgProfile, StackChange, DomainEntityMap
├── org_classifier.py    # Rules engine + future ML classifier
├── org_decoders.py      # Titus base64, MSIP labels, Proofpoint versions, antispam
├── plocamium_bridge.py  # Emit OrgInfraSignal events
└── models.py            # Extended with new dataclasses
```

### Data Flow

1. `scan` command processes emails → `EmailAnalysis` (existing)
2. `org_profiler.extract_stack(raw_headers, analysis)` → `InfraStack` snapshot
3. `org_store.upsert(domain, stack)` → compares against stored profile, returns `list[StackChange]`
4. If changes detected: `org_classifier.classify(change)` → `ChangeClassification`
5. If changes detected: print inline alert during scan (Rich formatting)
6. Entity resolution: `org_store.resolve_entity(domain)` → checks Plocamium entity map, manual overrides, or falls back to display name
7. Optionally: `plocamium_bridge.emit(signal)` → writes `OrgInfraSignal` as JSON for content engine pickup

### Raw Headers Pass-Through

The existing `parser.py` returns `EmailAnalysis` which doesn't preserve raw headers. The `org_profiler` needs access to the full raw header text to extract enterprise metadata (Titus, Proofpoint, Exchange routing headers). Solution: pass raw headers alongside the `EmailAnalysis` — the profiler receives both.

## Component Details

### Header Extraction (`org_profiler.py`)

Extracts `InfraStack` from raw email headers by detecting:

**MTA Vendor/Version:**
- Microsoft Exchange: `X-MS-Exchange-*` headers, version from `Received:` lines (e.g., `id 15.2.2562.37`)
- Google: `X-Google-*` headers, `X-Gm-Message-State`
- Postfix: `Received: from ... (Postfix)` pattern
- Sendmail: version in `Received:` line

**Email Platform:**
- M365: `*.prod.outlook.com` in Received headers, `X-MS-Exchange-CrossTenant-*` headers
- Google Workspace: `mx.google.com` in Received, `X-Google-DKIM-Signature`
- On-prem Exchange: Exchange headers without `outlook.com` routing

**Security Gateway:**
- Proofpoint: `X-Proofpoint-Virus-Version` header → parse `vendor=baseguard engine=ICAP:X.X.X,Aquarius:X.X.X,Hydra:X.X.X,FMLib:X.X.X`
- Mimecast: `X-Mimecast-*` headers
- Barracuda: `X-Barracuda-*` headers
- Cisco IronPort: `X-IronPort-*` headers

**TLS:** Parsed from `Received:` headers — `version=TLS1_2, cipher=...`

**DMARC Policy:** From `Authentication-Results` header — `dmarc=pass (p=REJECT sp=REJECT)`

**DLP System:** Titus (`X-Titus-Metadata-40`), MSIP (`Msip_Labels`), Forcepoint, Boldon James

**Tenant ID:** From `X-MS-Exchange-CrossTenant-Id`

**Antispam:** From `X-Microsoft-Antispam` (`BCL:0`) and `X-Forefront-Antispam-Report` (`SCL:1`)

### Decoders (`org_decoders.py`)

**Titus:** Base64 decode `X-Titus-Metadata-40` → JSON with namespace, classification properties (Aud, SE, CR), TMC version.

**MSIP:** Parse `Msip_Labels` header — semicolon-delimited key=value pairs. Extract label name (`Internal GS`), method, enabled state, set date.

**Proofpoint:** Parse `X-Proofpoint-Virus-Version` — extract individual engine names and versions as dict.

**Antispam:** Parse `BCL` (Bulk Complaint Level 0-9), `SCL` (Spam Confidence Level 0-9), `SFS` codes from `X-Forefront-Antispam-Report`.

### Storage (`org_store.py`)

SQLite at `~/.email-intel/orgs.db` with tables:

```sql
CREATE TABLE org_profiles (
    domain TEXT PRIMARY KEY,
    display_name TEXT,
    entity_id TEXT,
    sector TEXT,
    entity_source TEXT DEFAULT 'inferred',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    email_count INTEGER DEFAULT 0,
    current_stack TEXT NOT NULL  -- JSON serialized InfraStack
);

CREATE TABLE stack_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    field TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    signal TEXT,           -- positive, negative, neutral
    confidence REAL,
    reasoning TEXT,
    category TEXT,
    FOREIGN KEY (domain) REFERENCES org_profiles(domain)
);

CREATE TABLE domain_entity_map (
    domain TEXT PRIMARY KEY,
    entity_id TEXT,
    entity_name TEXT NOT NULL,
    sector TEXT,
    source TEXT DEFAULT 'manual'  -- plocamium, manual, inferred
);
```

**Upsert logic:** On each email processed, extract `InfraStack`, compare field-by-field against `current_stack` in `org_profiles`. For each changed field, insert a `stack_changes` row. Update `current_stack`, `last_seen`, and `email_count`.

### Change Classifier (`org_classifier.py`)

**v1: Rules engine**

```python
RULES = {
    # Positive signals (investment/modernization)
    "dmarc_policy": {
        ("none", "quarantine"): ("positive", "security", "DMARC strengthened to quarantine"),
        ("none", "reject"): ("positive", "security", "DMARC strengthened to reject"),
        ("quarantine", "reject"): ("positive", "security", "DMARC hardened to reject"),
    },
    "tls_version": {
        ("TLS1_0", "TLS1_2"): ("positive", "modernization", "TLS upgraded"),
        ("TLS1_2", "TLS1_3"): ("positive", "modernization", "TLS upgraded to 1.3"),
    },
    "email_platform": {
        ("on-prem-exchange", "m365"): ("positive", "migration", "Cloud migration to M365"),
        ("on-prem-exchange", "google-workspace"): ("positive", "migration", "Cloud migration to Google"),
    },
    # Negative signals (cost-cutting/degradation)
    "dmarc_policy": {
        ("reject", "quarantine"): ("negative", "security", "DMARC weakened"),
        ("reject", "none"): ("negative", "security", "DMARC removed"),
    },
    "tls_version": {
        ("TLS1_3", "TLS1_2"): ("negative", "security", "TLS downgraded"),
    },
}
```

Rules match on `(field, old_value, new_value)`. Unmatched changes default to `neutral`/`maintenance`.

Special logic:
- Security gateway **added** = positive/security
- Security gateway **removed** = negative/cost-cut
- DLP system **added** = positive/security (compliance investment)
- MTA version bump within 60 days of release = positive/maintenance (active patching)
- MTA version >1 year behind latest = negative/maintenance (stale)

**v2: Trained classifier** — once 50-100+ labeled changes accumulate, train a scikit-learn model (same pattern as Plocamium momentum scorer). Features: field name, old/new value categories, org sector, time since last change.

### Entity Resolution

**Resolution order:**
1. Check `domain_entity_map` table for manual/plocamium mappings
2. Query Plocamium entity store by domain (if bridge is configured)
3. Fall back to display name from `From:` header, flag as `source=inferred`

**CLI for manual mapping:**
```bash
email-intel orgs map gs.com "Goldman Sachs" --sector "Financial Services"
```

### Plocamium Bridge (`plocamium_bridge.py`)

Emits `OrgInfraSignal` as JSON. Two output modes:

- **Local file:** Appends to `~/.email-intel/signals.jsonl` (one signal per line). Content engine reads this as a signal source.
- **S3:** Writes to configured S3 bucket/prefix (for production pipeline integration).

Configured via `~/.email-intel/config.toml`:

```toml
[plocamium]
enabled = false
output = "local"            # local | s3
local_path = ""             # default: ~/.email-intel/signals.jsonl
s3_bucket = ""
s3_prefix = "email-intel/"
```

Content engine integration:
- Signal maps to existing entity via `entity_id`
- Momentum scorer treats infra changes as weighted signals: positive=+1, negative=-1, neutral=0
- Cross-org correlation: if multiple entities in same sector show similar changes in same time window, flag as sector trend

### CLI Extensions

**New commands:**

```bash
# List all profiled orgs (sorted by last seen)
email-intel orgs

# Detailed profile for a specific org
email-intel orgs gs.com

# Recent changes across all orgs
email-intel changes
email-intel changes --days 30
email-intel changes --signal positive

# Map a domain to an entity
email-intel orgs map gs.com "Goldman Sachs" --sector "Financial Services"

# Export all profiles
email-intel orgs export --format json -o orgs.json
```

**Inline alerts during scan:**

When `email-intel scan` detects org changes, it prints them inline:

```
⚠ Goldman Sachs (gs.com): Proofpoint upgraded Hydra 6.0.51→6.1.51 [positive/security]
⚠ Citadel (citadel.com): DMARC weakened reject→quarantine [negative/security]
✓ JPMorgan (jpmorgan.com): TLS cipher rotated [neutral/maintenance]
```

**Existing `scan` command changes:**

The `scan` command gets a `--profile` flag (default on) that enables org profiling during scans. The raw headers are passed through to the org profiler alongside the `EmailAnalysis`.

## Error Handling

- Unparseable enterprise headers → skip that field, log warning, don't fail the profile
- Missing Titus/MSIP data → `dlp_system=None`, no error
- Entity resolution fails → use display name, flag as `source=inferred`
- SQLite locked → retry once, then skip org update with warning
- Plocamium bridge failures → log and continue, never block scan

## Configuration

Extensions to `~/.email-intel/config.toml`:

```toml
[orgs]
enabled = true              # enable org profiling during scans
db_path = ""                # default: ~/.email-intel/orgs.db

[plocamium]
enabled = false
output = "local"
local_path = ""
s3_bucket = ""
s3_prefix = "email-intel/"
```

## Future (Not in v2 Scope)

- Dashboard with org timelines and sector heat maps
- Active DNS probing for domains without emails
- Trained ML classifier replacing rules engine
- Microsoft tenant ID → org name resolution via Azure AD
- Automated Plocamium entity creation for new orgs
