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
