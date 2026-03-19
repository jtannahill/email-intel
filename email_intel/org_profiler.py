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
    if msg.get("X-MS-Exchange-CrossTenant-Id") or msg.get("X-MS-Exchange-Organization-SCL") is not None:
        version = None
        match = re.search(r"Microsoft SMTP Server.*?id\s+([\d.]+)", raw)
        if match:
            version = match.group(1)
        return "Microsoft Exchange", version

    if "google.com" in raw.lower() and ("mx.google.com" in raw or msg.get("X-Gm-Message-State")):
        return "Google", None

    if "(Postfix)" in raw:
        return "Postfix", None

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
    pp = msg.get("X-Proofpoint-Virus-Version")
    if pp:
        engines = decode_proofpoint(pp)
        version_str = ", ".join(f"{k}:{v}" for k, v in engines.items()) if engines else pp
        return "Proofpoint", version_str

    for key in msg.keys():
        if key.lower().startswith("x-mimecast"):
            return "Mimecast", None

    for key in msg.keys():
        if key.lower().startswith("x-barracuda"):
            return "Barracuda", None

    for key in msg.keys():
        if key.lower().startswith("x-ironport"):
            return "Cisco IronPort", None

    return None, None


def detect_tls(raw: str) -> tuple[str | None, str | None]:
    version_match = re.search(r"version=(TLS[v]?[\d_.]+)", raw, re.IGNORECASE)
    cipher_match = re.search(r"cipher=([A-Z0-9_]+)", raw)

    version = None
    if version_match:
        v = version_match.group(1).upper().replace("V", "").replace(".", "_")
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

    tenant_id = msg.get("X-MS-Exchange-CrossTenant-Id")

    dkim_domains: list[str] = []
    auth_header = msg.get("Authentication-Results", "")
    for match in re.finditer(r"dkim=\w+\s+header\.i=@([\w.-]+)", auth_header):
        dkim_domains.append(match.group(1))

    spf_result = analysis.auth.spf if analysis.auth else None

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
        dlp_metadata["msip"] = decode_msip(msip_raw)

    antispam_scores = decode_antispam(
        msg.get("X-Microsoft-Antispam", ""),
        msg.get("X-Forefront-Antispam-Report", ""),
    )

    proofpoint_engines = None
    pp_raw = msg.get("X-Proofpoint-Virus-Version")
    if pp_raw:
        proofpoint_engines = decode_proofpoint(pp_raw)

    return InfraStack(
        mta_vendor=mta_vendor, mta_version=mta_version,
        email_platform=platform, security_gateway=gateway,
        security_gateway_version=gateway_version,
        tls_version=tls_version, tls_cipher=tls_cipher,
        dmarc_policy=dmarc_policy, spf_result=spf_result,
        dkim_domains=dkim_domains, dlp_system=dlp_system,
        dlp_metadata=dlp_metadata, tenant_id=tenant_id,
        antispam_scores=antispam_scores,
        proofpoint_engines=proofpoint_engines,
        observed_at=datetime.now(tz=timezone.utc),
    )
