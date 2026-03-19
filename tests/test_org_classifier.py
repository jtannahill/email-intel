from datetime import datetime, timezone
from email_intel.org_classifier import classify_change
from email_intel.models import StackChange


def _change(field, old, new) -> StackChange:
    return StackChange(id=1, domain="test.com", timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc),
        field=field, old_value=old, new_value=new)

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
