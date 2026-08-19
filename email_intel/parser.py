from __future__ import annotations
import email
import ipaddress
import re
from datetime import datetime, timezone
from email.message import Message
from email.utils import parseaddr, parsedate_to_datetime

from email_intel.models import AuthResult, EmailAnalysis, ServerHop

_IP_RE = re.compile(
    r"\[?"
    r"("
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"
    r"|::1"
    r")"
    r"\]?"
)

# Matches only IPv4 addresses (used to prefer IPv4 over IPv6 in origination scan)
_IPV4_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")

_RECEIVED_FROM_RE = re.compile(r"from\s+([\w\-\.]+)")
_RECEIVED_PROTO_RE = re.compile(r"with\s+(E?SMTP\w*)", re.IGNORECASE)
_RECEIVED_DATE_RE = re.compile(r";\s*(.+)$", re.MULTILINE)

_MSGID_CLIENTS: dict[str, str] = {
    "mail.gmail.com": "Gmail",
    "outlook.com": "Outlook",
    "yahoo.com": "Yahoo Mail",
    "icloud.com": "Apple iCloud",
    "protonmail.com": "ProtonMail",
    "fastmail.com": "FastMail",
}

_TZ_NAMES: dict[str, str] = {
    "+0000": "UTC", "-0400": "EDT", "-0500": "EST/CDT",
    "-0600": "CST/MDT", "-0700": "MST/PDT", "-0800": "PST",
    "+0100": "CET", "+0200": "EET", "+0530": "IST",
    "+0800": "CST/SGT", "+0900": "JST/KST", "+1000": "AEST",
}


_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_private_ip(ip_str: str) -> bool:
    """Return True if the IP is a well-known private/loopback/link-local range
    (RFC 1918, loopback, link-local, ULA) or is not a valid IP address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _RFC1918)
    except ValueError:
        # Not a valid IP address: treat as non-routable / skip it
        return True


def extract_hops(msg: Message) -> list[ServerHop]:
    received_headers = msg.get_all("Received", [])
    hops: list[ServerHop] = []

    for header in reversed(received_headers):
        header_str = " ".join(header.split())

        server_match = _RECEIVED_FROM_RE.search(header_str)
        server = server_match.group(1) if server_match else "unknown"

        ip_match = _IP_RE.search(header_str)
        ip = ip_match.group(1) if ip_match else None

        proto_match = _RECEIVED_PROTO_RE.search(header_str)
        protocol = proto_match.group(1) if proto_match else None

        date_match = _RECEIVED_DATE_RE.search(header_str)
        timestamp = None
        if date_match:
            try:
                timestamp = parsedate_to_datetime(date_match.group(1).strip())
            except (ValueError, TypeError):
                pass

        hops.append(ServerHop(
            server=server, ip=ip, timestamp=timestamp,
            protocol=protocol, latency_ms=None,
        ))

    for i in range(1, len(hops)):
        if hops[i].timestamp and hops[i - 1].timestamp:
            try:
                delta = (hops[i].timestamp - hops[i - 1].timestamp).total_seconds()
                hops[i].latency_ms = round(delta * 1000, 1)
            except TypeError:
                pass  # mixed naive/aware datetimes

    return hops


def extract_originating_ip(msg: Message, hops: list[ServerHop]) -> str | None:
    x_orig = msg.get("X-Originating-IP", "")
    if x_orig:
        ip_match = _IPV4_RE.search(x_orig) or _IP_RE.search(x_orig)
        if ip_match:
            ip = ip_match.group(1)
            if not is_private_ip(ip):
                return ip

    # Scan Received headers from innermost outward (reversed = bottom-of-email first).
    # Prefer IPv4 addresses; fall back to any valid non-private IP in each header.
    received_headers = msg.get_all("Received", [])
    for header in reversed(received_headers):
        header_str = " ".join(header.split())
        # Try IPv4 first within this header
        for match in _IPV4_RE.finditer(header_str):
            ip = match.group(1)
            if not is_private_ip(ip):
                return ip

    return None


def extract_auth(msg: Message) -> AuthResult:
    auth_header = msg.get("Authentication-Results", "")
    if not auth_header:
        return AuthResult()

    auth_lower = auth_header.lower()

    def _find_result(key: str) -> str | None:
        pattern = re.compile(rf"\b{key}=([\w]+)")
        match = pattern.search(auth_lower)
        return match.group(1) if match else None

    return AuthResult(
        spf=_find_result("spf"),
        dkim=_find_result("dkim"),
        dmarc=_find_result("dmarc"),
    )


def extract_timezone(msg: Message) -> tuple[str | None, str | None]:
    date_str = msg.get("Date", "")
    if not date_str:
        return None, None

    match = re.search(r"([+-]\d{4})", date_str)
    offset = match.group(1) if match else None
    name = _TZ_NAMES.get(offset, None) if offset else None
    return offset, name


def extract_mail_client(msg: Message) -> str | None:
    x_mailer = msg.get("X-Mailer")
    if x_mailer:
        return x_mailer.strip()

    user_agent = msg.get("User-Agent")
    if user_agent:
        return user_agent.strip()

    msg_id = msg.get("Message-ID", "")
    at_idx = msg_id.rfind("@")
    if at_idx > 0:
        domain = msg_id[at_idx + 1:].rstrip(">").lower()
        if domain in _MSGID_CLIENTS:
            return _MSGID_CLIENTS[domain]

    return "Unknown"


def detect_reply_to_mismatch(msg: Message) -> bool:
    from_addr = parseaddr(msg.get("From", ""))[1].lower()
    reply_to = parseaddr(msg.get("Reply-To", ""))[1].lower()
    if not reply_to or not from_addr:
        return False
    from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    reply_domain = reply_to.split("@")[-1] if "@" in reply_to else ""
    return from_domain != reply_domain


def detect_bulk(msg: Message) -> bool:
    if msg.get("List-Unsubscribe"):
        return True
    if msg.get("X-Campaign-ID") or msg.get("X-Mailgun-Sid"):
        return True
    if msg.get("Precedence", "").lower() in ("bulk", "list"):
        return True
    return False


def parse_headers(raw_headers: str) -> EmailAnalysis:
    msg = email.message_from_string(raw_headers)

    _, from_addr = parseaddr(msg.get("From", ""))
    _, to_addr = parseaddr(msg.get("To", ""))
    subject = msg.get("Subject")
    message_id = msg.get("Message-ID")

    date = None
    date_str = msg.get("Date")
    if date_str:
        try:
            date = parsedate_to_datetime(date_str)
        except (ValueError, TypeError):
            pass

    hops = extract_hops(msg)
    originating_ip = extract_originating_ip(msg, hops)
    auth = extract_auth(msg)
    tz_offset, tz_name = extract_timezone(msg)
    mail_client = extract_mail_client(msg)
    reply_to_mismatch = detect_reply_to_mismatch(msg)
    is_bulk = detect_bulk(msg)

    flags: list[str] = []
    if not hops:
        flags.append("No Received headers")
    if reply_to_mismatch:
        flags.append("Reply-To domain mismatch")
    if auth.spf and auth.spf not in ("pass",):
        flags.append(f"SPF {auth.spf}")
    if auth.dkim and auth.dkim not in ("pass",):
        flags.append(f"DKIM {auth.dkim}")
    if auth.dmarc and auth.dmarc not in ("pass",):
        flags.append(f"DMARC {auth.dmarc}")

    return EmailAnalysis(
        message_id=message_id,
        from_addr=from_addr or None,
        to_addr=to_addr or None,
        subject=subject,
        date=date,
        timezone_offset=tz_offset,
        timezone_name=tz_name,
        mail_client=mail_client,
        hops=hops,
        originating_ip=originating_ip,
        geo=None,
        auth=auth,
        reply_to_mismatch=reply_to_mismatch,
        is_bulk=is_bulk,
        flags=flags,
        raw_headers=raw_headers,
    )
