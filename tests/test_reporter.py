import json
import csv
import io
from datetime import datetime, timezone
from email_intel.reporter import (
    render_analysis,
    render_scan_summary,
    export_json,
    export_csv,
    build_scan_summary,
)
from email_intel.models import (
    EmailAnalysis, AuthResult, GeoResult, ServerHop, ScanSummary,
)


def _make_analysis(**overrides) -> EmailAnalysis:
    defaults = dict(
        message_id="<test@mail.gmail.com>",
        from_addr="sender@example.com",
        to_addr="me@test.com",
        subject="Test",
        date=datetime(2026, 3, 19, 14, 30, 0, tzinfo=timezone.utc),
        timezone_offset="-0500",
        timezone_name="EST",
        mail_client="Gmail",
        hops=[],
        originating_ip="74.125.82.42",
        geo=GeoResult(
            ip="74.125.82.42", city="Mountain View", region="California",
            country="US", lat=37.386, lon=-122.084,
            isp="Google LLC", org="Google LLC", source="ip-api",
        ),
        auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"),
        reply_to_mismatch=False,
        is_bulk=False,
        flags=[],
    )
    defaults.update(overrides)
    return EmailAnalysis(**defaults)


def test_render_analysis_returns_string():
    analysis = _make_analysis()
    output = render_analysis(analysis)
    assert "sender@example.com" in output
    assert "Mountain View" in output
    assert "SPF" in output


def test_render_analysis_with_flags():
    analysis = _make_analysis(flags=["Reply-To domain mismatch", "DMARC fail"])
    output = render_analysis(analysis)
    assert "Reply-To domain mismatch" in output


def test_build_scan_summary():
    emails = [
        _make_analysis(from_addr="a@test.com", mail_client="Gmail"),
        _make_analysis(from_addr="b@test.com", mail_client="Outlook"),
        _make_analysis(from_addr="c@test.com", mail_client="Gmail",
                       flags=["DMARC fail"]),
    ]
    summary = build_scan_summary(emails)
    assert summary.total_messages == 3
    assert ("Mountain View, US", 3) in summary.top_locations
    assert summary.client_breakdown["Gmail"] == 2
    assert summary.client_breakdown["Outlook"] == 1
    assert len(summary.flagged_messages) == 1


def test_export_json():
    analysis = _make_analysis()
    output = export_json([analysis])
    data = json.loads(output)
    assert len(data) == 1
    assert data[0]["from_addr"] == "sender@example.com"


def test_export_csv():
    analysis = _make_analysis()
    output = export_csv([analysis])
    reader = csv.DictReader(io.StringIO(output))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["from_addr"] == "sender@example.com"
    assert rows[0]["geo_city"] == "Mountain View"
