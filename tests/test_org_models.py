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
        mta_vendor="Google", mta_version=None, email_platform="google-workspace",
        security_gateway=None, security_gateway_version=None,
        tls_version="TLS1_3", tls_cipher="TLS_AES_256_GCM_SHA384",
        dmarc_policy="reject", spf_result="pass",
        dkim_domains=["google.com", "example.com"],
        dlp_system=None, dlp_metadata={}, tenant_id=None,
        antispam_scores={}, proofpoint_engines=None,
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
    change = StackChange(id=1, domain="gs.com", timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc),
        field="dmarc_policy", old_value="quarantine", new_value="reject")
    cls = ChangeClassification(change=change, signal="positive", confidence=1.0,
        reasoning="DMARC hardened to reject", category="security")
    assert cls.signal == "positive"


def test_domain_entity_map_creation():
    mapping = DomainEntityMap(domain="gs.com", entity_id="ent_123",
        entity_name="Goldman Sachs", sector="Financial Services", source="manual")
    assert mapping.entity_name == "Goldman Sachs"


def test_org_infra_signal_creation():
    change = StackChange(id=42, domain="gs.com", timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc),
        field="dmarc_policy", old_value="quarantine", new_value="reject")
    cls = ChangeClassification(change=change, signal="positive", confidence=1.0,
        reasoning="DMARC hardened", category="security")
    signal = OrgInfraSignal(signal_id=42, domain="gs.com", entity_id="ent_123",
        entity_name="Goldman Sachs", sector="Financial Services",
        change=change, classification=cls, timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc))
    assert signal.signal_id == 42


def test_email_analysis_has_raw_headers(gmail_headers):
    from email_intel.parser import parse_headers
    result = parse_headers(gmail_headers)
    assert result.raw_headers is not None
    assert "Received:" in result.raw_headers
