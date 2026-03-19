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
    assert changes == []
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
    assert changes[0].id is not None


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
    assert store.resolve_entity("unknown.com") is None


def test_get_recent_changes(tmp_path):
    store = OrgStore(db_path=str(tmp_path / "test.db"))
    stack1 = _make_stack(dmarc_policy="none")
    store.upsert("gs.com", stack1)
    stack2 = _make_stack(dmarc_policy="reject")
    store.upsert("gs.com", stack2)
    changes = store.get_changes(days=30)
    assert len(changes) >= 1
