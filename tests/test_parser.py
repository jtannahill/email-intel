import email
from email_intel.parser import (
    parse_headers,
    extract_hops,
    extract_originating_ip,
    extract_auth,
    extract_timezone,
    extract_mail_client,
    detect_reply_to_mismatch,
    detect_bulk,
    is_private_ip,
)


def test_parse_headers_returns_email_analysis(gmail_headers):
    result = parse_headers(gmail_headers)
    assert result.from_addr == "sender@example.com"
    assert result.to_addr == "me@gmail.com"
    assert result.subject == "Test Email for Analysis"


def test_extract_hops_gmail(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    hops = extract_hops(msg)
    assert len(hops) == 3
    assert hops[0].ip == "10.0.0.1"
    assert hops[1].ip == "209.85.128.182"


def test_extract_originating_ip_from_received(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    hops = extract_hops(msg)
    ip = extract_originating_ip(msg, hops)
    assert ip == "74.125.82.42"


def test_extract_originating_ip_from_x_originating(outlook_headers):
    msg = email.message_from_string(outlook_headers)
    hops = extract_hops(msg)
    ip = extract_originating_ip(msg, hops)
    assert ip == "203.0.113.45"


def test_extract_auth_pass(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    auth = extract_auth(msg)
    assert auth.spf == "pass"
    assert auth.dkim == "pass"
    assert auth.dmarc == "pass"


def test_extract_auth_fail(outlook_headers):
    msg = email.message_from_string(outlook_headers)
    auth = extract_auth(msg)
    assert auth.spf == "softfail"
    assert auth.dmarc == "fail"


def test_extract_timezone(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    offset, name = extract_timezone(msg)
    assert offset == "-0500"


def test_extract_mail_client_x_mailer(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    client = extract_mail_client(msg)
    assert "Apple Mail" in client


def test_extract_mail_client_message_id_fallback(outlook_headers):
    msg = email.message_from_string(outlook_headers)
    client = extract_mail_client(msg)
    assert client == "Outlook"


def test_detect_reply_to_mismatch_no_mismatch(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    assert detect_reply_to_mismatch(msg) is False


def test_detect_reply_to_mismatch_found(outlook_headers):
    msg = email.message_from_string(outlook_headers)
    assert detect_reply_to_mismatch(msg) is True


def test_detect_bulk_not_bulk(gmail_headers):
    msg = email.message_from_string(gmail_headers)
    assert detect_bulk(msg) is False


def test_detect_bulk_detected(outlook_headers):
    msg = email.message_from_string(outlook_headers)
    assert detect_bulk(msg) is True


def test_is_private_ip():
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("74.125.82.42") is False
    assert is_private_ip("::1") is True
    assert is_private_ip("fc00::1") is True
    assert is_private_ip("2607:f8b0:4004::1") is False


def test_parse_headers_minimal(minimal_headers):
    result = parse_headers(minimal_headers)
    assert result.from_addr == "bare@example.com"
    assert result.hops == []
    assert result.originating_ip is None
    assert "No Received headers" in result.flags
