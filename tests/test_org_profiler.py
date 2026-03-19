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
