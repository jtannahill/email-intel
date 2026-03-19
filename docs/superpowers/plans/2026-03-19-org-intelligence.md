# Org Intelligence Tracker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add passive org infrastructure profiling to email-intel — extract email security stacks from headers, track changes over time, classify them as investment signals, and bridge to Plocamium content engine.

**Architecture:** Five new modules (org_decoders, org_profiler, org_store, org_classifier, plocamium_bridge) + extensions to models.py, config.py, cli.py, and parser.py. Each email scanned produces an InfraStack snapshot; diffs against stored profiles generate classified StackChanges emitted as signals.

**Tech Stack:** Python 3.11+, SQLite3, dataclasses, base64/json (stdlib), existing Click/Rich CLI

**Spec:** `docs/superpowers/specs/2026-03-19-org-intelligence-design.md`

---

## File Structure

```
email_intel/
├── models.py            # MODIFY: add InfraStack, OrgProfile, StackChange, ChangeClassification, DomainEntityMap, OrgInfraSignal + raw_headers on EmailAnalysis
├── config.py            # MODIFY: add orgs + plocamium config sections
├── parser.py            # MODIFY: store raw_headers on EmailAnalysis
├── org_decoders.py      # CREATE: Titus, MSIP, Proofpoint, Antispam decoders
├── org_profiler.py      # CREATE: header → InfraStack extraction
├── org_store.py         # CREATE: SQLite CRUD for org profiles, changes, entity map
├── org_classifier.py    # CREATE: rules-based change classifier
├── plocamium_bridge.py  # CREATE: signal emission (local JSONL + S3)
├── cli.py               # MODIFY: add orgs, changes commands + --profile on scan
tests/
├── conftest.py          # MODIFY: add Goldman Sachs enterprise header fixture
├── test_org_decoders.py # CREATE
├── test_org_profiler.py # CREATE
├── test_org_store.py    # CREATE
├── test_org_classifier.py # CREATE
├── test_plocamium_bridge.py # CREATE
├── test_cli_orgs.py     # CREATE
```

---

### Task 1: Extend Models + Raw Headers Pass-Through

**Files:**
- Modify: `email_intel/models.py`
- Modify: `email_intel/parser.py`
- Modify: `tests/conftest.py`
- Create: `tests/test_org_models.py`

- [ ] **Step 1: Write failing tests for new models**

```python
# tests/test_org_models.py
import json
from datetime import datetime, timezone
from email_intel.models import (
    InfraStack, OrgProfile, StackChange, ChangeClassification,
    DomainEntityMap, OrgInfraSignal,
)


def test_infra_stack_creation():
    stack = InfraStack(
        mta_vendor="Microsoft Exchange",
        mta_version="15.2.2562.37",
        email_platform="m365",
        security_gateway="Proofpoint",
        security_gateway_version="Hydra:6.1.51",
        tls_version="TLS1_2",
        tls_cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        dmarc_policy="reject",
        spf_result="pass",
        dkim_domains=["gs.com"],
        dlp_system="Titus",
        dlp_metadata={"Aud": "UNR"},
        tenant_id="38651f6f-836b-4bdf-9615-4e255c290fea",
        antispam_scores={"BCL": 0, "SCL": 1},
        proofpoint_engines={"Aquarius": "18.0.1143", "Hydra": "6.1.51"},
        observed_at=datetime(2026, 3, 19, 16, 0, 0, tzinfo=timezone.utc),
    )
    assert stack.mta_vendor == "Microsoft Exchange"
    assert stack.dkim_domains == ["gs.com"]


def test_infra_stack_to_json_roundtrip():
    stack = InfraStack(
        mta_vendor="Google",
        mta_version=None,
        email_platform="google-workspace",
        security_gateway=None,
        security_gateway_version=None,
        tls_version="TLS1_3",
        tls_cipher="TLS_AES_256_GCM_SHA384",
        dmarc_policy="reject",
        spf_result="pass",
        dkim_domains=["google.com", "example.com"],
        dlp_system=None,
        dlp_metadata={},
        tenant_id=None,
        antispam_scores={},
        proofpoint_engines=None,
        observed_at=datetime(2026, 3, 19, 12, 0, 0, tzinfo=timezone.utc),
    )
    j = stack.to_json()
    restored = InfraStack.from_json(j)
    assert restored.mta_vendor == "Google"
    assert restored.dkim_domains == ["google.com", "example.com"]
    assert restored.observed_at == stack.observed_at


def test_stack_change_creation():
    change = StackChange(
        id=None, domain="gs.com",
        timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc),
        field="dmarc_policy", old_value="quarantine", new_value="reject",
    )
    assert change.field == "dmarc_policy"
    assert change.id is None


def test_change_classification_creation():
    change = StackChange(
        id=1, domain="gs.com",
        timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc),
        field="dmarc_policy", old_value="quarantine", new_value="reject",
    )
    cls = ChangeClassification(
        change=change, signal="positive", confidence=1.0,
        reasoning="DMARC hardened to reject", category="security",
    )
    assert cls.signal == "positive"


def test_domain_entity_map_creation():
    mapping = DomainEntityMap(
        domain="gs.com", entity_id="ent_123",
        entity_name="Goldman Sachs", sector="Financial Services",
        source="manual",
    )
    assert mapping.entity_name == "Goldman Sachs"


def test_org_infra_signal_creation():
    change = StackChange(
        id=42, domain="gs.com",
        timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc),
        field="dmarc_policy", old_value="quarantine", new_value="reject",
    )
    cls = ChangeClassification(
        change=change, signal="positive", confidence=1.0,
        reasoning="DMARC hardened", category="security",
    )
    signal = OrgInfraSignal(
        signal_id=42, domain="gs.com", entity_id="ent_123",
        entity_name="Goldman Sachs", sector="Financial Services",
        change=change, classification=cls,
        timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc),
    )
    assert signal.signal_id == 42


def test_email_analysis_has_raw_headers(gmail_headers):
    from email_intel.parser import parse_headers
    result = parse_headers(gmail_headers)
    assert result.raw_headers is not None
    assert "Received:" in result.raw_headers
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jamest/email-intel && python3 -m pytest tests/test_org_models.py -v`
Expected: FAIL — `ImportError: cannot import name 'InfraStack'`

- [ ] **Step 3: Add new dataclasses to `email_intel/models.py`**

Add after `ScanSummary` class, plus add `raw_headers` field to `EmailAnalysis`:

```python
# Add to EmailAnalysis, after flags field:
    raw_headers: str | None = None

# New dataclasses at end of file:

@dataclass
class InfraStack:
    mta_vendor: str | None
    mta_version: str | None
    email_platform: str | None
    security_gateway: str | None
    security_gateway_version: str | None
    tls_version: str | None
    tls_cipher: str | None
    dmarc_policy: str | None
    spf_result: str | None
    dkim_domains: list[str] = field(default_factory=list)
    dlp_system: str | None = None
    dlp_metadata: dict = field(default_factory=dict)
    tenant_id: str | None = None
    antispam_scores: dict = field(default_factory=dict)
    proofpoint_engines: dict | None = None
    observed_at: datetime | None = None

    def to_json(self) -> str:
        import json
        from dataclasses import asdict
        d = asdict(self)
        if d.get("observed_at"):
            d["observed_at"] = d["observed_at"].isoformat()
        return json.dumps(d)

    @classmethod
    def from_json(cls, text: str) -> InfraStack:
        import json
        from datetime import datetime
        d = json.loads(text)
        if d.get("observed_at"):
            d["observed_at"] = datetime.fromisoformat(d["observed_at"])
        return cls(**d)


@dataclass
class StackChange:
    id: int | None
    domain: str
    timestamp: datetime
    field: str
    old_value: str | None
    new_value: str | None


@dataclass
class ChangeClassification:
    change: StackChange
    signal: str             # positive, negative, neutral
    confidence: float
    reasoning: str
    category: str           # modernization, security, migration, cost-cut, maintenance


@dataclass
class DomainEntityMap:
    domain: str
    entity_id: str | None
    entity_name: str
    sector: str | None
    source: str             # plocamium, manual, inferred


@dataclass
class OrgProfile:
    domain: str
    display_name: str | None
    entity_id: str | None
    sector: str | None
    entity_source: str
    first_seen: datetime
    last_seen: datetime
    email_count: int
    current_stack: InfraStack


@dataclass
class OrgInfraSignal:
    signal_id: int | None
    domain: str
    entity_id: str | None
    entity_name: str
    sector: str | None
    change: StackChange
    classification: ChangeClassification
    timestamp: datetime
```

- [ ] **Step 4: Modify `parser.py` to store raw_headers**

In `email_intel/parser.py`, find the `return EmailAnalysis(...)` call at the end of `parse_headers()` and add `raw_headers=raw_headers` as the last keyword argument. The exact edit:

Replace:
```python
        flags=flags,
    )
```
at the end of `parse_headers()` with:
```python
        flags=flags,
        raw_headers=raw_headers,
    )
```

- [ ] **Step 5: Run tests and verify pass**

Run: `python3 -m pytest tests/test_org_models.py tests/test_models.py tests/test_parser.py tests/test_cli.py -v`
Expected: All pass (existing tests unaffected due to default `None`)

- [ ] **Step 6: Add enterprise header fixture to conftest.py**

Add to `tests/conftest.py`:

```python
SAMPLE_HEADERS_GOLDMAN = """\
From: "Yetter, Julia" <Julia.Yetter@gs.com>
To: jtannahill@plocamium.com
Subject: Goldman Sachs Apex Family Office Symposium
Date: Thu, 19 Mar 2026 16:02:01 +0000
Message-Id: <LV3PR19MB82782B39A81C83E557C15BA6844FALV3PR19MB8278.namprd19.prod.outlook.com>
Authentication-Results: mx.google.com; dkim=pass header.i=@gs.com header.s=201802 header.b=Fldn79x9; spf=pass (google.com: domain of julia.yetter@gs.com designates 138.8.105.144 as permitted sender) smtp.mailfrom=Julia.Yetter@gs.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gs.com
X-MS-Exchange-CrossTenant-Id: 38651f6f-836b-4bdf-9615-4e255c290fea
X-MS-Exchange-CrossTenant-AuthSource: LV3PR19MB8278.namprd19.prod.outlook.com
X-Proofpoint-Virus-Version: vendor=baseguard engine=ICAP:2.0.293,Aquarius:18.0.1143,Hydra:6.1.51,FMLib:17.12.100.49 definitions=2026-03-19_02,2026-03-19_05,2025-10-01_01
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014;
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR19MB8278.namprd19.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014);DIR:OUT;SFP:1101;
Msip_Labels: MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_Enabled=true;MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_Name=Internal GS;MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_SetDate=2026-03-19T15:51:22Z;MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_Method=Standard;
X-Titus-Metadata-40: eyJDYXRlZ29yeUxhYmVscyI6IiIsIk1ldGFkYXRhIjp7Im5zIjoiaHR0cDpcL1wvd3d3LnRpdHVzLmNvbVwvbnNcL0dvbGRtYW5TYWNocyIsImlkIjoiMmJiNzhhMWItOTMyNS00MTg5LWFkMGEtMGE3MDgyMmMxMTE4IiwicHJvcHMiOlt7Im4iOiJBdWQiLCJ2YWxzIjpbeyJ2YWx1ZSI6IlVOUiJ9XX0seyJuIjoiU0UiLCJ2YWxzIjpbeyJ2YWx1ZSI6Ik4ifV19LHsibiI6IkNSIiwidmFscyI6W119XX0sIlN1YmplY3RMYWJlbHMiOltdLCJUTUNWZXJzaW9uIjoiMjMuNi4yNDAzLjEiLCJUcnVzdGVkTGFiZWxIYXNoIjoiTEdHS1hvUW9OcGk2WHFWNkY2ZytaQ1B2YjBidzdkb1YyNUNvUUZ5QmdGTmplWWYzV3BUaFNEd2wydjY2RFhnWCJ9
Received: from mxe14.gs.com (mxe14.gs.com. [138.8.105.144]) by mx.google.com with ESMTPS id d2e1a72fcca58 for <jtannahill@plocamium.com> (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128); Thu, 19 Mar 2026 09:02:09 -0700 (PDT)
Received: from exhy64417-068.firmwide.corp.gs.com (exhy64417-068.dc.gs.com [10.155.139.215]) by ppa-n-003-d178811.dc.gs.com (PPS) with ESMTPS id 4cw1abn9yr-1 (version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT) for <jtannahill@plocamium.com>; Thu, 19 Mar 2026 12:02:05 -0400
Received: from LV3PR19MB8278.namprd19.prod.outlook.com (2603:10b6:408:1a5::17) by PH0PR19MB5646.namprd19.prod.outlook.com (2603:10b6:510:144::20) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9723.19; Thu, 19 Mar 2026 16:02:01 +0000
"""


@pytest.fixture
def goldman_headers():
    return SAMPLE_HEADERS_GOLDMAN
```

- [ ] **Step 7: Commit**

```bash
git add email_intel/models.py email_intel/parser.py tests/conftest.py tests/test_org_models.py
git commit -m "feat: extend models with org intelligence dataclasses + raw_headers pass-through"
```

---

### Task 2: Enterprise Header Decoders

**Files:**
- Create: `email_intel/org_decoders.py`
- Create: `tests/test_org_decoders.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_org_decoders.py
from email_intel.org_decoders import (
    decode_titus,
    decode_msip,
    decode_proofpoint,
    decode_antispam,
)


def test_decode_titus():
    raw = "eyJDYXRlZ29yeUxhYmVscyI6IiIsIk1ldGFkYXRhIjp7Im5zIjoiaHR0cDpcL1wvd3d3LnRpdHVzLmNvbVwvbnNcL0dvbGRtYW5TYWNocyIsImlkIjoiMmJiNzhhMWItOTMyNS00MTg5LWFkMGEtMGE3MDgyMmMxMTE4IiwicHJvcHMiOlt7Im4iOiJBdWQiLCJ2YWxzIjpbeyJ2YWx1ZSI6IlVOUiJ9XX0seyJuIjoiU0UiLCJ2YWxzIjpbeyJ2YWx1ZSI6Ik4ifV19LHsibiI6IkNSIiwidmFscyI6W119XX0sIlN1YmplY3RMYWJlbHMiOltdLCJUTUNWZXJzaW9uIjoiMjMuNi4yNDAzLjEiLCJUcnVzdGVkTGFiZWxIYXNoIjoiTEdHS1hvUW9OcGk2WHFWNkY2ZytaQ1B2YjBidzdkb1YyNUNvUUZ5QmdGTmplWWYzV3BUaFNEd2wydjY2RFhnWCJ9"
    result = decode_titus(raw)
    assert result["namespace"] == "http://www.titus.com/ns/GoldmanSachs"
    assert result["Aud"] == "UNR"
    assert result["SE"] == "N"
    assert result["tmc_version"] == "23.6.2403.1"


def test_decode_titus_invalid():
    result = decode_titus("not-base64!!!")
    assert result == {}


def test_decode_msip():
    raw = "MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_Enabled=true;MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_Name=Internal GS;MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_SetDate=2026-03-19T15:51:22Z;MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_Method=Standard;"
    result = decode_msip(raw)
    assert result["label_name"] == "Internal GS"
    assert result["enabled"] is True
    assert result["method"] == "Standard"
    assert result["label_id"] == "a64882d5-5c68-43ae-b974-91da18426e9b"


def test_decode_msip_empty():
    result = decode_msip("")
    assert result == {}


def test_decode_proofpoint():
    raw = "vendor=baseguard engine=ICAP:2.0.293,Aquarius:18.0.1143,Hydra:6.1.51,FMLib:17.12.100.49 definitions=2026-03-19_02,2026-03-19_05,2025-10-01_01"
    result = decode_proofpoint(raw)
    assert result["ICAP"] == "2.0.293"
    assert result["Aquarius"] == "18.0.1143"
    assert result["Hydra"] == "6.1.51"
    assert result["FMLib"] == "17.12.100.49"


def test_decode_proofpoint_empty():
    result = decode_proofpoint("")
    assert result == {}


def test_decode_antispam():
    antispam = "BCL:0;ARA:13230040|1800799024|376014;"
    forefront = "CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR19MB8278.namprd19.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014);DIR:OUT;SFP:1101;"
    result = decode_antispam(antispam, forefront)
    assert result["BCL"] == 0
    assert result["SCL"] == 1


def test_decode_antispam_missing():
    result = decode_antispam("", "")
    assert result == {}
```

- [ ] **Step 2: Run to verify fail**

Run: `python3 -m pytest tests/test_org_decoders.py -v`
Expected: FAIL

- [ ] **Step 3: Write `email_intel/org_decoders.py`**

```python
from __future__ import annotations
import base64
import json
import logging
import re

logger = logging.getLogger(__name__)


def decode_titus(raw_b64: str) -> dict:
    if not raw_b64:
        return {}
    try:
        decoded = base64.b64decode(raw_b64).decode("utf-8")
        data = json.loads(decoded)
        result: dict = {}
        metadata = data.get("Metadata", {})
        result["namespace"] = metadata.get("ns", "")
        result["id"] = metadata.get("id", "")
        for prop in metadata.get("props", []):
            name = prop.get("n", "")
            vals = prop.get("vals", [])
            if vals:
                result[name] = vals[0].get("value", "")
            else:
                result[name] = ""
        result["tmc_version"] = data.get("TMCVersion", "")
        return result
    except Exception as e:
        logger.warning("Failed to decode Titus metadata: %s", e)
        return {}


def decode_msip(raw: str) -> dict:
    if not raw or not raw.strip():
        return {}
    try:
        result: dict = {}
        label_id = None
        for part in raw.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip()
            value = value.strip()
            # Extract label ID from key pattern: MSIP_Label_{uuid}_FieldName
            if label_id is None:
                match = re.search(r"MSIP_Label_([a-f0-9\-]+)_", key)
                if match:
                    label_id = match.group(1)
            if key.endswith("_Name"):
                result["label_name"] = value
            elif key.endswith("_Enabled"):
                result["enabled"] = value.lower() == "true"
            elif key.endswith("_Method"):
                result["method"] = value
            elif key.endswith("_SetDate"):
                result["set_date"] = value
        if label_id:
            result["label_id"] = label_id
        return result
    except Exception as e:
        logger.warning("Failed to decode MSIP labels: %s", e)
        return {}


def decode_proofpoint(raw: str) -> dict:
    if not raw:
        return {}
    try:
        match = re.search(r"engine=(.+?)(?:\s+definitions=|\s*$)", raw)
        if not match:
            return {}
        engines_str = match.group(1)
        result: dict = {}
        for part in engines_str.split(","):
            if ":" in part:
                name, version = part.split(":", 1)
                result[name.strip()] = version.strip()
        return result
    except Exception as e:
        logger.warning("Failed to decode Proofpoint version: %s", e)
        return {}


def decode_antispam(antispam_header: str, forefront_header: str) -> dict:
    if not antispam_header and not forefront_header:
        return {}
    result: dict = {}
    try:
        # Parse BCL from X-Microsoft-Antispam
        bcl_match = re.search(r"BCL:(\d+)", antispam_header)
        if bcl_match:
            result["BCL"] = int(bcl_match.group(1))
        # Parse SCL from X-Forefront-Antispam-Report
        scl_match = re.search(r"SCL:(\d+)", forefront_header)
        if scl_match:
            result["SCL"] = int(scl_match.group(1))
    except Exception as e:
        logger.warning("Failed to decode antispam: %s", e)
    return result
```

- [ ] **Step 4: Run tests and verify pass**

Run: `python3 -m pytest tests/test_org_decoders.py -v`
Expected: All 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/org_decoders.py tests/test_org_decoders.py
git commit -m "feat: enterprise header decoders — Titus, MSIP, Proofpoint, antispam"
```

---

### Task 3: Org Profiler — Header → InfraStack

**Files:**
- Create: `email_intel/org_profiler.py`
- Create: `tests/test_org_profiler.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_org_profiler.py
import email
from email_intel.org_profiler import extract_stack, detect_mta, detect_platform, detect_security_gateway, detect_tls, detect_dmarc_policy, extract_domain


def test_extract_domain():
    assert extract_domain("julia.yetter@gs.com") == "gs.com"
    assert extract_domain("user@sub.example.co.uk") == "sub.example.co.uk"
    assert extract_domain(None) is None
    assert extract_domain("") is None


def test_detect_mta_exchange(goldman_headers):
    msg = email.message_from_string(goldman_headers)
    vendor, version = detect_mta(msg, goldman_headers)
    assert vendor == "Microsoft Exchange"
    assert version is not None
    assert "15.20" in version or "15.2" in version


def test_detect_mta_google(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    vendor, version = detect_mta(msg, gmail_headers)
    assert vendor == "Google"


def test_detect_platform_m365(goldman_headers):
    msg = email.message_from_string(goldman_headers)
    platform = detect_platform(msg, goldman_headers)
    assert platform == "m365"


def test_detect_platform_google(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    platform = detect_platform(msg, gmail_headers)
    assert platform == "google-workspace"


def test_detect_security_gateway_proofpoint(goldman_headers):
    msg = email.message_from_string(goldman_headers)
    gateway, version = detect_security_gateway(msg)
    assert gateway == "Proofpoint"
    assert version is not None


def test_detect_security_gateway_none(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    gateway, version = detect_security_gateway(msg)
    assert gateway is None


def test_detect_tls(goldman_headers):
    version, cipher = detect_tls(goldman_headers)
    assert version == "TLS1_2"
    assert cipher is not None


def test_detect_dmarc_policy(goldman_headers):
    msg = email.message_from_string(goldman_headers)
    policy = detect_dmarc_policy(msg)
    assert policy == "reject"


def test_extract_stack_goldman(goldman_headers):
    from email_intel.parser import parse_headers
    analysis = parse_headers(goldman_headers)
    stack = extract_stack(goldman_headers, analysis)
    assert stack.mta_vendor == "Microsoft Exchange"
    assert stack.email_platform == "m365"
    assert stack.security_gateway == "Proofpoint"
    assert stack.dmarc_policy == "reject"
    assert stack.tenant_id == "38651f6f-836b-4bdf-9615-4e255c290fea"
    assert stack.dlp_system == "Titus"
    assert stack.antispam_scores.get("BCL") == 0
    assert len(stack.dkim_domains) > 0


def test_extract_stack_minimal(minimal_headers):
    from email_intel.parser import parse_headers
    analysis = parse_headers(minimal_headers)
    stack = extract_stack(minimal_headers, analysis)
    assert stack.mta_vendor is None
    assert stack.security_gateway is None
    assert stack.dmarc_policy is None
```

- [ ] **Step 2: Run to verify fail**

Run: `python3 -m pytest tests/test_org_profiler.py -v`
Expected: FAIL

- [ ] **Step 3: Write `email_intel/org_profiler.py`**

```python
from __future__ import annotations
import email
import logging
import re
from datetime import datetime, timezone
from email.message import Message

from email_intel.models import EmailAnalysis, InfraStack
from email_intel.org_decoders import decode_titus, decode_msip, decode_proofpoint, decode_antispam

logger = logging.getLogger(__name__)


def extract_domain(email_addr: str | None) -> str | None:
    if not email_addr or "@" not in email_addr:
        return None
    return email_addr.split("@", 1)[1].lower()


def detect_mta(msg: Message, raw: str) -> tuple[str | None, str | None]:
    # Microsoft Exchange
    if msg.get("X-MS-Exchange-CrossTenant-Id") or msg.get("X-MS-Exchange-Organization-SCL") is not None:
        version = None
        # Try to extract version from Received headers
        match = re.search(r"Microsoft SMTP Server.*?id\s+([\d.]+)", raw)
        if match:
            version = match.group(1)
        return "Microsoft Exchange", version

    # Google
    if "google.com" in raw.lower() and ("mx.google.com" in raw or msg.get("X-Gm-Message-State")):
        return "Google", None

    # Postfix
    if "(Postfix)" in raw:
        return "Postfix", None

    # Sendmail
    match = re.search(r"Sendmail\s+([\d.]+)", raw)
    if match:
        return "Sendmail", match.group(1)

    return None, None


def detect_platform(msg: Message, raw: str) -> str | None:
    has_exchange = bool(msg.get("X-MS-Exchange-CrossTenant-Id"))
    has_outlook = "prod.outlook.com" in raw or "protection.outlook.com" in raw

    if has_exchange and has_outlook:
        return "m365"
    if has_exchange and not has_outlook:
        return "on-prem-exchange"
    if "mx.google.com" in raw or msg.get("X-Gm-Message-State"):
        return "google-workspace"
    return "other"


def detect_security_gateway(msg: Message) -> tuple[str | None, str | None]:
    # Proofpoint
    pp = msg.get("X-Proofpoint-Virus-Version")
    if pp:
        engines = decode_proofpoint(pp)
        version_str = ", ".join(f"{k}:{v}" for k, v in engines.items()) if engines else pp
        return "Proofpoint", version_str

    # Mimecast
    for key in msg.keys():
        if key.lower().startswith("x-mimecast"):
            return "Mimecast", None

    # Barracuda
    for key in msg.keys():
        if key.lower().startswith("x-barracuda"):
            return "Barracuda", None

    # Cisco IronPort
    for key in msg.keys():
        if key.lower().startswith("x-ironport"):
            return "Cisco IronPort", None

    return None, None


def detect_tls(raw: str) -> tuple[str | None, str | None]:
    # Look for version=TLSx_y and cipher=... in Received headers
    version_match = re.search(r"version=(TLS[v]?[\d_.]+)", raw, re.IGNORECASE)
    cipher_match = re.search(r"cipher=([A-Z0-9_]+)", raw)

    version = None
    if version_match:
        v = version_match.group(1).upper().replace("V", "").replace(".", "_")
        # Normalize: TLS1_2, TLS1_3
        if "1_2" in v or "12" in v:
            version = "TLS1_2"
        elif "1_3" in v or "13" in v:
            version = "TLS1_3"
        elif "1_0" in v or "10" in v:
            version = "TLS1_0"
        elif "1_1" in v or "11" in v:
            version = "TLS1_1"
        else:
            version = version_match.group(1)

    cipher = cipher_match.group(1) if cipher_match else None
    return version, cipher


def detect_dmarc_policy(msg: Message) -> str | None:
    auth = msg.get("Authentication-Results", "")
    if not auth:
        return None
    # Look for p=REJECT, p=QUARANTINE, p=NONE
    match = re.search(r"dmarc=\w+\s*\(p=(\w+)", auth, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


def extract_stack(raw_headers: str, analysis: EmailAnalysis) -> InfraStack:
    msg = email.message_from_string(raw_headers)

    mta_vendor, mta_version = detect_mta(msg, raw_headers)
    platform = detect_platform(msg, raw_headers)
    gateway, gateway_version = detect_security_gateway(msg)
    tls_version, tls_cipher = detect_tls(raw_headers)
    dmarc_policy = detect_dmarc_policy(msg)

    # Tenant ID
    tenant_id = msg.get("X-MS-Exchange-CrossTenant-Id")

    # DKIM domains from Authentication-Results
    dkim_domains: list[str] = []
    auth_header = msg.get("Authentication-Results", "")
    for match in re.finditer(r"dkim=\w+\s+header\.i=@([\w.-]+)", auth_header):
        dkim_domains.append(match.group(1))

    # SPF from existing analysis
    spf_result = analysis.auth.spf if analysis.auth else None

    # DLP
    dlp_system = None
    dlp_metadata: dict = {}
    titus_raw = msg.get("X-Titus-Metadata-40")
    if titus_raw:
        dlp_system = "Titus"
        dlp_metadata = decode_titus(titus_raw)
    msip_raw = msg.get("Msip_Labels")
    if msip_raw and not dlp_system:
        dlp_system = "MSIP"
        dlp_metadata = decode_msip(msip_raw)
    elif msip_raw and dlp_system == "Titus":
        # Both present — Titus is primary, add MSIP data
        dlp_metadata["msip"] = decode_msip(msip_raw)

    # Antispam
    antispam_scores = decode_antispam(
        msg.get("X-Microsoft-Antispam", ""),
        msg.get("X-Forefront-Antispam-Report", ""),
    )

    # Proofpoint engines
    proofpoint_engines = None
    pp_raw = msg.get("X-Proofpoint-Virus-Version")
    if pp_raw:
        proofpoint_engines = decode_proofpoint(pp_raw)

    return InfraStack(
        mta_vendor=mta_vendor,
        mta_version=mta_version,
        email_platform=platform,
        security_gateway=gateway,
        security_gateway_version=gateway_version,
        tls_version=tls_version,
        tls_cipher=tls_cipher,
        dmarc_policy=dmarc_policy,
        spf_result=spf_result,
        dkim_domains=dkim_domains,
        dlp_system=dlp_system,
        dlp_metadata=dlp_metadata,
        tenant_id=tenant_id,
        antispam_scores=antispam_scores,
        proofpoint_engines=proofpoint_engines,
        observed_at=datetime.now(tz=timezone.utc),
    )
```

- [ ] **Step 4: Run tests and verify pass**

Run: `python3 -m pytest tests/test_org_profiler.py -v`
Expected: All 12 tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/org_profiler.py tests/test_org_profiler.py
git commit -m "feat: org profiler — header extraction to InfraStack"
```

---

### Task 4: Org Store — SQLite CRUD

**Files:**
- Create: `email_intel/org_store.py`
- Create: `tests/test_org_store.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_org_store.py
from datetime import datetime, timezone
from email_intel.org_store import OrgStore
from email_intel.models import InfraStack, StackChange, DomainEntityMap


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


def test_upsert_new_org(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "test.db"))
    stack = _make_stack()
    changes = store.upsert("gs.com", stack)
    assert changes == []  # first time, no changes

    profile = store.get_profile("gs.com")
    assert profile is not None
    assert profile.domain == "gs.com"
    assert profile.email_count == 1
    assert profile.current_stack.mta_vendor == "Microsoft Exchange"


def test_upsert_detects_change(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "test.db"))
    stack1 = _make_stack(dmarc_policy="quarantine")
    store.upsert("gs.com", stack1)

    stack2 = _make_stack(dmarc_policy="reject")
    changes = store.upsert("gs.com", stack2)
    assert len(changes) == 1
    assert changes[0].field == "dmarc_policy"
    assert changes[0].old_value == "quarantine"
    assert changes[0].new_value == "reject"
    assert changes[0].id is not None  # populated from SQLite


def test_upsert_increments_count(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "test.db"))
    stack = _make_stack()
    store.upsert("gs.com", stack)
    store.upsert("gs.com", stack)
    store.upsert("gs.com", stack)
    profile = store.get_profile("gs.com")
    assert profile.email_count == 3


def test_classify_change(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "test.db"))
    stack1 = _make_stack(dmarc_policy="quarantine")
    store.upsert("gs.com", stack1)
    stack2 = _make_stack(dmarc_policy="reject")
    changes = store.upsert("gs.com", stack2)

    store.classify_change(changes[0].id, "positive", 1.0, "DMARC hardened", "security")
    history = store.get_changes("gs.com")
    assert history[0].id == changes[0].id
    # Verify classification was stored
    row = store._get_change_row(changes[0].id)
    assert row["signal"] == "positive"
    assert row["category"] == "security"


def test_list_profiles(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "test.db"))
    store.upsert("gs.com", _make_stack())
    store.upsert("jpmorgan.com", _make_stack(mta_vendor="Google"))
    profiles = store.list_profiles()
    assert len(profiles) == 2
    domains = {p.domain for p in profiles}
    assert "gs.com" in domains
    assert "jpmorgan.com" in domains


def test_get_changes_filtered(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "test.db"))
    stack1 = _make_stack(dmarc_policy="none", tls_version="TLS1_0")
    store.upsert("gs.com", stack1)
    stack2 = _make_stack(dmarc_policy="reject", tls_version="TLS1_2")
    changes = store.upsert("gs.com", stack2)
    assert len(changes) == 2

    all_changes = store.get_changes()
    assert len(all_changes) == 2

    gs_changes = store.get_changes(domain="gs.com")
    assert len(gs_changes) == 2


def test_entity_map_crud(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "test.db"))
    store.set_entity_mapping("gs.com", "Goldman Sachs", entity_id="ent_1", sector="Finance", source="manual")

    mapping = store.resolve_entity("gs.com")
    assert mapping is not None
    assert mapping.entity_name == "Goldman Sachs"
    assert mapping.sector == "Finance"

    # Unknown domain
    assert store.resolve_entity("unknown.com") is None


def test_get_recent_changes(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "test.db"))
    stack1 = _make_stack(dmarc_policy="none")
    store.upsert("gs.com", stack1)
    stack2 = _make_stack(dmarc_policy="reject")
    store.upsert("gs.com", stack2)

    changes = store.get_changes(days=30)
    assert len(changes) >= 1
```

- [ ] **Step 2: Run to verify fail**

Run: `python3 -m pytest tests/test_org_store.py -v`
Expected: FAIL

- [ ] **Step 3: Write `email_intel/org_store.py`**

```python
from __future__ import annotations
import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from email_intel.models import (
    DomainEntityMap, InfraStack, OrgProfile, StackChange,
)

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path.home() / ".email-intel" / "orgs.db"

# Fields to compare for change detection (skip observed_at, dlp_metadata, antispam_scores, proofpoint_engines)
_TRACKED_FIELDS = [
    "mta_vendor", "mta_version", "email_platform",
    "security_gateway", "security_gateway_version",
    "tls_version", "tls_cipher", "dmarc_policy", "spf_result",
    "dlp_system", "tenant_id",
]


class OrgStore:
    def __init__(self, db_path: str | None = None):
        self._db_path = db_path or str(_DEFAULT_DB)
        parent = Path(self._db_path).parent
        parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            try:
                os.chmod(str(parent), 0o700)
            except OSError:
                pass
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def _init_db(self):
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS org_profiles (
                domain TEXT PRIMARY KEY,
                display_name TEXT,
                entity_id TEXT,
                sector TEXT,
                entity_source TEXT DEFAULT 'inferred',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                email_count INTEGER DEFAULT 0,
                current_stack TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stack_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                field TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                signal TEXT,
                confidence REAL,
                reasoning TEXT,
                category TEXT,
                FOREIGN KEY (domain) REFERENCES org_profiles(domain)
            );
            CREATE INDEX IF NOT EXISTS idx_stack_changes_domain ON stack_changes(domain);
            CREATE INDEX IF NOT EXISTS idx_stack_changes_timestamp ON stack_changes(timestamp);
            CREATE TABLE IF NOT EXISTS domain_entity_map (
                domain TEXT PRIMARY KEY,
                entity_id TEXT,
                entity_name TEXT NOT NULL,
                sector TEXT,
                source TEXT DEFAULT 'manual'
            );
        """)
        conn.commit()
        conn.close()

    def upsert(self, domain: str, stack: InfraStack) -> list[StackChange]:
        conn = self._conn()
        now = datetime.now(tz=timezone.utc).isoformat()
        stack_json = stack.to_json()

        row = conn.execute("SELECT * FROM org_profiles WHERE domain = ?", (domain,)).fetchone()

        if row is None:
            # New org
            conn.execute(
                "INSERT INTO org_profiles (domain, display_name, first_seen, last_seen, email_count, current_stack) VALUES (?, ?, ?, ?, 1, ?)",
                (domain, domain, now, now, stack_json),
            )
            conn.commit()
            conn.close()
            return []

        # Existing org — diff
        old_stack = InfraStack.from_json(row["current_stack"])
        changes: list[StackChange] = []

        for field in _TRACKED_FIELDS:
            old_val = getattr(old_stack, field)
            new_val = getattr(stack, field)
            # Normalize for comparison
            old_str = str(old_val) if old_val is not None else None
            new_str = str(new_val) if new_val is not None else None
            if old_str != new_str:
                cursor = conn.execute(
                    "INSERT INTO stack_changes (domain, timestamp, field, old_value, new_value) VALUES (?, ?, ?, ?, ?)",
                    (domain, now, field, old_str, new_str),
                )
                changes.append(StackChange(
                    id=cursor.lastrowid, domain=domain,
                    timestamp=datetime.fromisoformat(now),
                    field=field, old_value=old_str, new_value=new_str,
                ))

        # Also detect dkim_domains changes (list field)
        old_dkim = sorted(old_stack.dkim_domains)
        new_dkim = sorted(stack.dkim_domains)
        if old_dkim != new_dkim:
            cursor = conn.execute(
                "INSERT INTO stack_changes (domain, timestamp, field, old_value, new_value) VALUES (?, ?, ?, ?, ?)",
                (domain, now, "dkim_domains", ",".join(old_dkim), ",".join(new_dkim)),
            )
            changes.append(StackChange(
                id=cursor.lastrowid, domain=domain,
                timestamp=datetime.fromisoformat(now),
                field="dkim_domains", old_value=",".join(old_dkim), new_value=",".join(new_dkim),
            ))

        conn.execute(
            "UPDATE org_profiles SET last_seen = ?, email_count = email_count + 1, current_stack = ? WHERE domain = ?",
            (now, stack_json, domain),
        )
        conn.commit()
        conn.close()
        return changes

    def classify_change(self, change_id: int, signal: str, confidence: float, reasoning: str, category: str):
        conn = self._conn()
        conn.execute(
            "UPDATE stack_changes SET signal = ?, confidence = ?, reasoning = ?, category = ? WHERE id = ?",
            (signal, confidence, reasoning, category, change_id),
        )
        conn.commit()
        conn.close()

    def get_profile(self, domain: str) -> OrgProfile | None:
        conn = self._conn()
        row = conn.execute("SELECT * FROM org_profiles WHERE domain = ?", (domain,)).fetchone()
        conn.close()
        if not row:
            return None
        return self._row_to_profile(row)

    def list_profiles(self) -> list[OrgProfile]:
        conn = self._conn()
        rows = conn.execute("SELECT * FROM org_profiles ORDER BY last_seen DESC").fetchall()
        conn.close()
        return [self._row_to_profile(r) for r in rows]

    def get_changes(self, domain: str | None = None, days: int | None = None, signal: str | None = None) -> list[StackChange]:
        conn = self._conn()
        query = "SELECT * FROM stack_changes WHERE 1=1"
        params: list = []
        if domain:
            query += " AND domain = ?"
            params.append(domain)
        if days:
            cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=days)).isoformat()
            query += " AND timestamp >= ?"
            params.append(cutoff)
        if signal:
            query += " AND signal = ?"
            params.append(signal)
        query += " ORDER BY timestamp DESC"

        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [
            StackChange(
                id=r["id"], domain=r["domain"],
                timestamp=datetime.fromisoformat(r["timestamp"]),
                field=r["field"], old_value=r["old_value"], new_value=r["new_value"],
            )
            for r in rows
        ]

    def _get_change_row(self, change_id: int) -> sqlite3.Row | None:
        conn = self._conn()
        row = conn.execute("SELECT * FROM stack_changes WHERE id = ?", (change_id,)).fetchone()
        conn.close()
        return row

    def set_entity_mapping(self, domain: str, entity_name: str, entity_id: str | None = None, sector: str | None = None, source: str = "manual"):
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO domain_entity_map (domain, entity_id, entity_name, sector, source) VALUES (?, ?, ?, ?, ?)",
            (domain, entity_id, entity_name, sector, source),
        )
        # Also update org_profiles if exists
        conn.execute(
            "UPDATE org_profiles SET display_name = ?, entity_id = ?, sector = ?, entity_source = ? WHERE domain = ?",
            (entity_name, entity_id, sector, source, domain),
        )
        conn.commit()
        conn.close()

    def resolve_entity(self, domain: str) -> DomainEntityMap | None:
        conn = self._conn()
        row = conn.execute("SELECT * FROM domain_entity_map WHERE domain = ?", (domain,)).fetchone()
        conn.close()
        if not row:
            return None
        return DomainEntityMap(
            domain=row["domain"], entity_id=row["entity_id"],
            entity_name=row["entity_name"], sector=row["sector"],
            source=row["source"],
        )

    def _row_to_profile(self, row: sqlite3.Row) -> OrgProfile:
        return OrgProfile(
            domain=row["domain"],
            display_name=row["display_name"],
            entity_id=row["entity_id"],
            sector=row["sector"],
            entity_source=row["entity_source"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            email_count=row["email_count"],
            current_stack=InfraStack.from_json(row["current_stack"]),
        )
```

- [ ] **Step 4: Run tests and verify pass**

Run: `python3 -m pytest tests/test_org_store.py -v`
Expected: All 9 tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/org_store.py tests/test_org_store.py
git commit -m "feat: org store — SQLite CRUD for profiles, changes, entity map"
```

---

### Task 5: Change Classifier — Rules Engine

**Files:**
- Create: `email_intel/org_classifier.py`
- Create: `tests/test_org_classifier.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_org_classifier.py
from datetime import datetime, timezone
from email_intel.org_classifier import classify_change
from email_intel.models import StackChange


def _change(field, old, new) -> StackChange:
    return StackChange(
        id=1, domain="test.com",
        timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc),
        field=field, old_value=old, new_value=new,
    )


def test_dmarc_strengthened():
    cls = classify_change(_change("dmarc_policy", "none", "reject"))
    assert cls.signal == "positive"
    assert cls.category == "security"


def test_dmarc_weakened():
    cls = classify_change(_change("dmarc_policy", "reject", "none"))
    assert cls.signal == "negative"
    assert cls.category == "security"


def test_tls_upgraded():
    cls = classify_change(_change("tls_version", "TLS1_2", "TLS1_3"))
    assert cls.signal == "positive"
    assert cls.category == "modernization"


def test_tls_downgraded():
    cls = classify_change(_change("tls_version", "TLS1_3", "TLS1_2"))
    assert cls.signal == "negative"


def test_cloud_migration():
    cls = classify_change(_change("email_platform", "on-prem-exchange", "m365"))
    assert cls.signal == "positive"
    assert cls.category == "migration"


def test_security_gateway_added():
    cls = classify_change(_change("security_gateway", None, "Proofpoint"))
    assert cls.signal == "positive"
    assert cls.category == "security"


def test_security_gateway_removed():
    cls = classify_change(_change("security_gateway", "Proofpoint", None))
    assert cls.signal == "negative"
    assert cls.category == "cost-cut"


def test_security_gateway_vendor_change():
    cls = classify_change(_change("security_gateway", "Mimecast", "Proofpoint"))
    assert cls.signal == "neutral"
    assert cls.category == "migration"


def test_dlp_added():
    cls = classify_change(_change("dlp_system", None, "Titus"))
    assert cls.signal == "positive"
    assert cls.category == "security"


def test_unknown_change_defaults_neutral():
    cls = classify_change(_change("tls_cipher", "AES128", "AES256"))
    assert cls.signal == "neutral"
    assert cls.category == "maintenance"


def test_mta_version_change_neutral():
    cls = classify_change(_change("mta_version", "15.2.2562.37", "15.2.2595.10"))
    assert cls.signal == "neutral"
    assert cls.category == "maintenance"
```

- [ ] **Step 2: Run to verify fail**

Run: `python3 -m pytest tests/test_org_classifier.py -v`
Expected: FAIL

- [ ] **Step 3: Write `email_intel/org_classifier.py`**

```python
from __future__ import annotations
from email_intel.models import ChangeClassification, StackChange

# Flat transition rules: (field, old, new, signal, category, reasoning)
TRANSITION_RULES: list[tuple[str, str, str, str, str, str]] = [
    # DMARC — positive
    ("dmarc_policy", "none", "quarantine", "positive", "security", "DMARC strengthened to quarantine"),
    ("dmarc_policy", "none", "reject", "positive", "security", "DMARC strengthened to reject"),
    ("dmarc_policy", "quarantine", "reject", "positive", "security", "DMARC hardened to reject"),
    # DMARC — negative
    ("dmarc_policy", "reject", "quarantine", "negative", "security", "DMARC weakened"),
    ("dmarc_policy", "reject", "none", "negative", "security", "DMARC removed"),
    ("dmarc_policy", "quarantine", "none", "negative", "security", "DMARC removed"),
    # TLS — positive
    ("tls_version", "TLS1_0", "TLS1_2", "positive", "modernization", "TLS upgraded"),
    ("tls_version", "TLS1_0", "TLS1_3", "positive", "modernization", "TLS upgraded to 1.3"),
    ("tls_version", "TLS1_2", "TLS1_3", "positive", "modernization", "TLS upgraded to 1.3"),
    # TLS — negative
    ("tls_version", "TLS1_3", "TLS1_2", "negative", "security", "TLS downgraded"),
    ("tls_version", "TLS1_2", "TLS1_0", "negative", "security", "TLS downgraded"),
    # Platform — positive
    ("email_platform", "on-prem-exchange", "m365", "positive", "migration", "Cloud migration to M365"),
    ("email_platform", "on-prem-exchange", "google-workspace", "positive", "migration", "Cloud migration to Google"),
    # Platform — negative
    ("email_platform", "m365", "on-prem-exchange", "negative", "cost-cut", "Cloud to on-prem regression"),
]

# Build lookup dict at import time
_RULE_MAP: dict[tuple[str, str | None, str | None], tuple[str, str, str]] = {
    (field, old, new): (signal, category, reasoning)
    for field, old, new, signal, category, reasoning in TRANSITION_RULES
}


def classify_change(change: StackChange) -> ChangeClassification:
    # 1. Check transition rules
    key = (change.field, change.old_value, change.new_value)
    if key in _RULE_MAP:
        signal, category, reasoning = _RULE_MAP[key]
        return ChangeClassification(
            change=change, signal=signal, confidence=1.0,
            reasoning=reasoning, category=category,
        )

    # 2. Presence/absence rules
    if change.field == "security_gateway":
        if change.old_value is None and change.new_value is not None:
            return ChangeClassification(
                change=change, signal="positive", confidence=0.9,
                reasoning=f"Security gateway added: {change.new_value}",
                category="security",
            )
        if change.old_value is not None and change.new_value is None:
            return ChangeClassification(
                change=change, signal="negative", confidence=0.9,
                reasoning=f"Security gateway removed: {change.old_value}",
                category="cost-cut",
            )
        # Vendor change (both non-None, different)
        if change.old_value and change.new_value:
            return ChangeClassification(
                change=change, signal="neutral", confidence=0.7,
                reasoning=f"Security gateway changed: {change.old_value} → {change.new_value}",
                category="migration",
            )

    if change.field == "dlp_system":
        if change.old_value is None and change.new_value is not None:
            return ChangeClassification(
                change=change, signal="positive", confidence=0.9,
                reasoning=f"DLP system added: {change.new_value}",
                category="security",
            )

    # 3. Default: neutral/maintenance
    return ChangeClassification(
        change=change, signal="neutral", confidence=0.5,
        reasoning=f"{change.field} changed: {change.old_value} → {change.new_value}",
        category="maintenance",
    )
```

- [ ] **Step 4: Run tests and verify pass**

Run: `python3 -m pytest tests/test_org_classifier.py -v`
Expected: All 11 tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/org_classifier.py tests/test_org_classifier.py
git commit -m "feat: change classifier — rules engine with transition + presence/absence logic"
```

---

### Task 6: Plocamium Bridge — Signal Emission

**Files:**
- Create: `email_intel/plocamium_bridge.py`
- Create: `tests/test_plocamium_bridge.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_plocamium_bridge.py
import json
from datetime import datetime, timezone
from email_intel.plocamium_bridge import PlocamiumBridge
from email_intel.models import StackChange, ChangeClassification, OrgInfraSignal


def _make_signal() -> OrgInfraSignal:
    change = StackChange(
        id=42, domain="gs.com",
        timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc),
        field="dmarc_policy", old_value="quarantine", new_value="reject",
    )
    cls = ChangeClassification(
        change=change, signal="positive", confidence=1.0,
        reasoning="DMARC hardened", category="security",
    )
    return OrgInfraSignal(
        signal_id=42, domain="gs.com", entity_id="ent_1",
        entity_name="Goldman Sachs", sector="Financial Services",
        change=change, classification=cls,
        timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc),
    )


def test_buffer_and_flush_local(tmp_path):
    output_path = str(tmp_path / "signals.jsonl")
    bridge = PlocamiumBridge(enabled=True, output="local", local_path=output_path)

    bridge.buffer(_make_signal())
    bridge.buffer(_make_signal())
    assert bridge.pending_count == 2

    bridge.flush()
    assert bridge.pending_count == 0

    with open(output_path) as f:
        lines = f.readlines()
    assert len(lines) == 2

    data = json.loads(lines[0])
    assert data["domain"] == "gs.com"
    assert data["signal"] == "positive"
    assert data["signal_id"] == 42


def test_disabled_bridge_no_output(tmp_path):
    output_path = str(tmp_path / "signals.jsonl")
    bridge = PlocamiumBridge(enabled=False, output="local", local_path=output_path)
    bridge.buffer(_make_signal())
    bridge.flush()
    import os
    assert not os.path.exists(output_path)


def test_flush_empty_buffer(tmp_path):
    output_path = str(tmp_path / "signals.jsonl")
    bridge = PlocamiumBridge(enabled=True, output="local", local_path=output_path)
    bridge.flush()  # no signals buffered
    import os
    assert not os.path.exists(output_path)
```

- [ ] **Step 2: Run to verify fail**

Run: `python3 -m pytest tests/test_plocamium_bridge.py -v`
Expected: FAIL

- [ ] **Step 3: Write `email_intel/plocamium_bridge.py`**

```python
from __future__ import annotations
import json
import logging
from datetime import datetime
from pathlib import Path

from email_intel.models import OrgInfraSignal

logger = logging.getLogger(__name__)

_DEFAULT_LOCAL_PATH = Path.home() / ".email-intel" / "signals.jsonl"


class PlocamiumBridge:
    def __init__(
        self,
        enabled: bool = False,
        output: str = "local",
        local_path: str | None = None,
        s3_bucket: str | None = None,
        s3_prefix: str = "email-intel/",
        s3_profile: str | None = None,
    ):
        self._enabled = enabled
        self._output = output
        self._local_path = local_path or str(_DEFAULT_LOCAL_PATH)
        self._s3_bucket = s3_bucket
        self._s3_prefix = s3_prefix
        self._s3_profile = s3_profile
        self._buffer: list[OrgInfraSignal] = []

    @property
    def pending_count(self) -> int:
        return len(self._buffer)

    def buffer(self, signal: OrgInfraSignal):
        if not self._enabled:
            return
        self._buffer.append(signal)

    def flush(self):
        if not self._enabled or not self._buffer:
            return

        if self._output == "local":
            self._flush_local()
        elif self._output == "s3":
            self._flush_s3()

        self._buffer.clear()

    def _signal_to_dict(self, signal: OrgInfraSignal) -> dict:
        return {
            "signal_id": signal.signal_id,
            "domain": signal.domain,
            "entity_id": signal.entity_id,
            "entity_name": signal.entity_name,
            "sector": signal.sector,
            "field": signal.change.field,
            "old_value": signal.change.old_value,
            "new_value": signal.change.new_value,
            "signal": signal.classification.signal,
            "confidence": signal.classification.confidence,
            "reasoning": signal.classification.reasoning,
            "category": signal.classification.category,
            "timestamp": signal.timestamp.isoformat(),
        }

    def _flush_local(self):
        try:
            path = Path(self._local_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a") as f:
                for signal in self._buffer:
                    f.write(json.dumps(self._signal_to_dict(signal)) + "\n")
            logger.info("Wrote %d signals to %s", len(self._buffer), self._local_path)
        except Exception as e:
            logger.error("Failed to write signals locally: %s", e)

    def _flush_s3(self):
        try:
            import boto3
            session_kwargs = {}
            if self._s3_profile:
                session_kwargs["profile_name"] = self._s3_profile
            session = boto3.Session(**session_kwargs)
            s3 = session.client("s3")

            body = "\n".join(
                json.dumps(self._signal_to_dict(s)) for s in self._buffer
            ) + "\n"

            key = f"{self._s3_prefix}signals-{datetime.now().strftime('%Y%m%d-%H%M%S')}.jsonl"
            s3.put_object(Bucket=self._s3_bucket, Key=key, Body=body.encode())
            logger.info("Wrote %d signals to s3://%s/%s", len(self._buffer), self._s3_bucket, key)
        except Exception as e:
            logger.error("Failed to write signals to S3: %s", e)
```

- [ ] **Step 4: Run tests and verify pass**

Run: `python3 -m pytest tests/test_plocamium_bridge.py -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/plocamium_bridge.py tests/test_plocamium_bridge.py
git commit -m "feat: Plocamium bridge — buffered signal emission to local JSONL + S3"
```

---

### Task 7: Extend Config for Org + Plocamium Sections

**Files:**
- Modify: `email_intel/config.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_config.py`:

```python
def test_config_org_defaults():
    cfg = load_config(config_path="/nonexistent/config.toml")
    assert cfg.orgs_enabled is True
    assert cfg.orgs_db_path is not None
    assert cfg.plocamium_enabled is False
    assert cfg.plocamium_output == "local"


def test_config_org_from_toml(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text("""
[orgs]
enabled = false
db_path = "/custom/orgs.db"

[plocamium]
enabled = true
output = "s3"
s3_bucket = "my-bucket"
s3_prefix = "signals/"
s3_profile = "prod"
""")
    cfg = load_config(config_path=str(config_file))
    assert cfg.orgs_enabled is False
    assert cfg.orgs_db_path == "/custom/orgs.db"
    assert cfg.plocamium_enabled is True
    assert cfg.plocamium_output == "s3"
    assert cfg.plocamium_s3_bucket == "my-bucket"
    assert cfg.plocamium_s3_profile == "prod"
```

- [ ] **Step 2: Run to verify fail**

Run: `python3 -m pytest tests/test_config.py -v`
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'orgs_enabled'`

- [ ] **Step 3: Extend `email_intel/config.py`**

Add new fields to `Config` dataclass:

```python
    # Org profiling
    orgs_enabled: bool = True
    orgs_db_path: str = str(_DEFAULT_DIR / "orgs.db")
    # Plocamium bridge
    plocamium_enabled: bool = False
    plocamium_output: str = "local"
    plocamium_local_path: str = str(_DEFAULT_DIR / "signals.jsonl")
    plocamium_s3_bucket: str = ""
    plocamium_s3_prefix: str = "email-intel/"
    plocamium_s3_profile: str = ""
```

Add to `load_config()` after the `defaults` section:

```python
        orgs = data.get("orgs", {})
        if "enabled" in orgs:
            cfg.orgs_enabled = orgs["enabled"]
        cfg.orgs_db_path = orgs.get("db_path") or cfg.orgs_db_path

        ploc = data.get("plocamium", {})
        if "enabled" in ploc:
            cfg.plocamium_enabled = ploc["enabled"]
        cfg.plocamium_output = ploc.get("output", cfg.plocamium_output)
        cfg.plocamium_local_path = ploc.get("local_path") or cfg.plocamium_local_path
        cfg.plocamium_s3_bucket = ploc.get("s3_bucket") or cfg.plocamium_s3_bucket
        cfg.plocamium_s3_prefix = ploc.get("s3_prefix", cfg.plocamium_s3_prefix)
        cfg.plocamium_s3_profile = ploc.get("s3_profile") or cfg.plocamium_s3_profile
```

- [ ] **Step 4: Run tests and verify pass**

Run: `python3 -m pytest tests/test_config.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/config.py tests/test_config.py
git commit -m "feat: extend config with org profiling + Plocamium bridge settings"
```

---

### Task 8: CLI Extensions — orgs, changes, scan --profile

**Files:**
- Modify: `email_intel/cli.py`
- Create: `tests/test_cli_orgs.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_cli_orgs.py
from unittest.mock import patch
from click.testing import CliRunner
from email_intel.cli import main
from email_intel.config import Config


def _test_config(tmp_path) -> Config:
    """Return a Config pointing at tmp_path for test isolation."""
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
        # Map first
        result = runner.invoke(main, [
            "orgs", "map", "gs.com", "Goldman Sachs",
            "--sector", "Financial Services",
        ])
        assert result.exit_code == 0

        # Show detail
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
```

- [ ] **Step 2: Run to verify fail**

Run: `python3 -m pytest tests/test_cli_orgs.py -v`
Expected: FAIL — no `orgs` command

- [ ] **Step 3: Extend `email_intel/cli.py`**

Add imports at top of cli.py:

```python
from email_intel.org_profiler import extract_stack, extract_domain
from email_intel.org_store import OrgStore
from email_intel.org_classifier import classify_change
from email_intel.plocamium_bridge import PlocamiumBridge
```

Add the `orgs` command group and `changes` command after the `auth` command:

```python
@main.group(invoke_without_command=True)
@click.pass_context
def orgs(ctx):
    """Org infrastructure profiles."""
    if ctx.invoked_subcommand is None:
        # List all orgs
        cfg = load_config()
        store = OrgStore(db_path=cfg.orgs_db_path)
        profiles = store.list_profiles()
        if not profiles:
            console.print("No org profiles yet. Run a scan to start profiling.")
            return
        from rich.table import Table
        table = Table(title=f"Org Profiles ({len(profiles)})")
        table.add_column("Domain")
        table.add_column("Name")
        table.add_column("Platform")
        table.add_column("Security")
        table.add_column("DMARC")
        table.add_column("Emails", justify="right")
        table.add_column("Last Seen")
        for p in profiles:
            s = p.current_stack
            table.add_row(
                p.domain,
                p.display_name or p.domain,
                s.email_platform or "?",
                s.security_gateway or "-",
                s.dmarc_policy or "?",
                str(p.email_count),
                p.last_seen.strftime("%Y-%m-%d"),
            )
        console.print(table)


@orgs.command("show")
@click.argument("domain")
def orgs_show(domain):
    """Show detailed profile for a specific org."""
    cfg = load_config()
    store = OrgStore(db_path=cfg.orgs_db_path)
    profile = store.get_profile(domain)
    entity = store.resolve_entity(domain)

    if not profile and not entity:
        console.print(f"No profile or entity mapping found for {domain}")
        return

    if entity:
        console.print(f"[bold]{entity.entity_name}[/bold] ({domain})")
        if entity.sector:
            console.print(f"Sector: {entity.sector}")
        console.print(f"Source: {entity.source}")
        console.print()

    if profile:
        s = profile.current_stack
        from rich.table import Table
        table = Table(title="Infrastructure Stack")
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("MTA", f"{s.mta_vendor or '?'} {s.mta_version or ''}")
        table.add_row("Platform", s.email_platform or "?")
        table.add_row("Security Gateway", f"{s.security_gateway or '-'} {s.security_gateway_version or ''}")
        table.add_row("TLS", f"{s.tls_version or '?'} / {s.tls_cipher or '?'}")
        table.add_row("DMARC", s.dmarc_policy or "?")
        table.add_row("DLP", s.dlp_system or "-")
        table.add_row("Tenant ID", s.tenant_id or "-")
        table.add_row("DKIM Domains", ", ".join(s.dkim_domains) if s.dkim_domains else "-")
        console.print(table)
        console.print(f"\nEmails observed: {profile.email_count}")
        console.print(f"First seen: {profile.first_seen.strftime('%Y-%m-%d')}")
        console.print(f"Last seen: {profile.last_seen.strftime('%Y-%m-%d')}")

        # Show recent changes
        changes = store.get_changes(domain=domain)
        if changes:
            console.print(f"\n[bold]Recent Changes ({len(changes)}):[/bold]")
            for c in changes[:10]:
                console.print(f"  {c.timestamp.strftime('%Y-%m-%d')} {c.field}: {c.old_value} → {c.new_value}")
    else:
        console.print(f"Entity mapped but no email profile yet. Run a scan to populate.")


@orgs.command("map")
@click.argument("domain")
@click.argument("name")
@click.option("--sector", help="Industry sector")
@click.option("--entity-id", help="Plocamium entity ID")
def orgs_map(domain, name, sector, entity_id):
    """Map a domain to an organization name."""
    cfg = load_config()
    store = OrgStore(db_path=cfg.orgs_db_path)
    store.set_entity_mapping(domain, name, entity_id=entity_id, sector=sector, source="manual")
    console.print(f"Mapped {domain} → {name}")


@orgs.command("export")
@click.option("--format", "fmt", type=click.Choice(["json", "csv"]), default="json")
@click.option("-o", "--output", "output_path", help="Output file path")
def orgs_export(fmt, output_path):
    """Export all org profiles."""
    cfg = load_config()
    store = OrgStore(db_path=cfg.orgs_db_path)
    profiles = store.list_profiles()

    import json as json_mod
    rows = []
    for p in profiles:
        s = p.current_stack
        rows.append({
            "domain": p.domain, "name": p.display_name,
            "entity_id": p.entity_id, "sector": p.sector,
            "platform": s.email_platform, "mta": s.mta_vendor,
            "security_gateway": s.security_gateway,
            "dmarc": s.dmarc_policy, "tls": s.tls_version,
            "dlp": s.dlp_system, "emails": p.email_count,
            "first_seen": p.first_seen.isoformat(),
            "last_seen": p.last_seen.isoformat(),
        })

    if fmt == "json":
        text = json_mod.dumps(rows, indent=2)
    else:
        import csv, io
        output = io.StringIO()
        if rows:
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        text = output.getvalue()

    if output_path:
        with open(output_path, "w") as f:
            f.write(text)
        console.print(f"Exported {len(profiles)} profiles to {output_path}")
    else:
        click.echo(text)


@main.command()
@click.option("--days", type=int, default=None, help="Filter to last N days")
@click.option("--signal", type=click.Choice(["positive", "negative", "neutral"]), help="Filter by signal")
@click.option("--domain", help="Filter by domain")
def changes(days, signal, domain):
    """Show recent org infrastructure changes."""
    cfg = load_config()
    store = OrgStore(db_path=cfg.orgs_db_path)
    change_list = store.get_changes(domain=domain, days=days, signal=signal)

    if not change_list:
        console.print("No changes found.")
        return

    from rich.table import Table
    table = Table(title=f"Infrastructure Changes ({len(change_list)})")
    table.add_column("Date")
    table.add_column("Domain")
    table.add_column("Field")
    table.add_column("Old")
    table.add_column("New")

    for c in change_list[:50]:
        table.add_row(
            c.timestamp.strftime("%Y-%m-%d"),
            c.domain, c.field,
            c.old_value or "-", c.new_value or "-",
        )
    console.print(table)
```

Also modify the `scan` command to add `--profile` flag and org profiling logic. Add to the `scan` function after geo resolution and before output:

```python
    # Org profiling
    if cfg.orgs_enabled:
        store = OrgStore(db_path=cfg.orgs_db_path)
        bridge = PlocamiumBridge(
            enabled=cfg.plocamium_enabled,
            output=cfg.plocamium_output,
            local_path=cfg.plocamium_local_path,
            s3_bucket=cfg.plocamium_s3_bucket,
            s3_prefix=cfg.plocamium_s3_prefix,
            s3_profile=cfg.plocamium_s3_profile,
        )

        for i, a in enumerate(analyses):
            domain = extract_domain(a.from_addr)
            if not domain:
                continue
            raw = raw_headers_list[i] if i < len(raw_headers_list) else None
            if not raw:
                continue
            try:
                stack = extract_stack(raw, a)
                org_changes = store.upsert(domain, stack)
                for ch in org_changes:
                    cls = classify_change(ch)
                    store.classify_change(ch.id, cls.signal, cls.confidence, cls.reasoning, cls.category)
                    # Inline alert
                    entity = store.resolve_entity(domain)
                    name = entity.entity_name if entity else domain
                    icon = "⚠" if cls.signal != "neutral" else "✓"
                    color = {"positive": "green", "negative": "red", "neutral": "dim"}.get(cls.signal, "")
                    console.print(f"[{color}]{icon} {name} ({domain}): {cls.reasoning} [{cls.signal}/{cls.category}][/{color}]")

                    if cfg.plocamium_enabled:
                        from email_intel.models import OrgInfraSignal
                        bridge.buffer(OrgInfraSignal(
                            signal_id=ch.id, domain=domain,
                            entity_id=entity.entity_id if entity else None,
                            entity_name=entity.entity_name if entity else domain,
                            sector=entity.sector if entity else None,
                            change=ch, classification=cls,
                            timestamp=ch.timestamp,
                        ))
            except Exception as e:
                logger.warning("Org profiling failed for %s: %s", domain, e)

        bridge.flush()
```

**Note:** `orgs sync-entities` (loading entity mappings from Plocamium JSON export) is deferred — manual `orgs map` covers the use case for now. Will add when the content engine export pipeline is wired.

Add `--profile/--no-profile` option to the scan command decorator:

```python
@click.option("--profile/--no-profile", default=True, help="Enable org profiling")
```

And pass it to the function, wrapping the org profiling block with `if profile and cfg.orgs_enabled:`.

- [ ] **Step 4: Run tests and verify pass**

Run: `python3 -m pytest tests/test_cli_orgs.py tests/test_cli.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add email_intel/cli.py tests/test_cli_orgs.py
git commit -m "feat: CLI extensions — orgs, changes, scan --profile with inline alerts"
```

---

### Task 9: Integration Test + Push

**Files:**
- None new

- [ ] **Step 1: Run full test suite**

Run: `python3 -m pytest tests/ -v --tb=short`
Expected: All tests PASS (43 existing + ~48 new ≈ 91 total)

- [ ] **Step 2: Test with real Goldman headers**

```bash
PYTHONPATH=/Users/jamest/email-intel python3 -c "
import sys
sys.argv = ['email-intel', 'analyze', '--format', 'json']
from email_intel.cli import main
main(standalone_mode=False)
" < /dev/stdin
```

Paste the Goldman headers — verify org profiling creates a profile in `~/.email-intel/orgs.db`.

Then check: `./run.sh orgs`

- [ ] **Step 3: Fix any issues found**

- [ ] **Step 4: Run full test suite again**

Run: `python3 -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 5: Final commit and push**

```bash
git add -A
git commit -m "test: integration tests and final polish for org intelligence"
git push origin main
```
