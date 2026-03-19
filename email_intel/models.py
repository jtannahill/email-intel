from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ServerHop:
    server: str
    ip: str | None
    timestamp: datetime | None
    protocol: str | None
    latency_ms: float | None


@dataclass
class AuthResult:
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None


@dataclass
class GeoResult:
    ip: str
    city: str | None
    region: str | None
    country: str | None
    lat: float | None
    lon: float | None
    isp: str | None
    org: str | None
    source: str


@dataclass
class EmailAnalysis:
    message_id: str | None
    from_addr: str | None
    to_addr: str | None
    subject: str | None
    date: datetime | None
    timezone_offset: str | None
    timezone_name: str | None
    mail_client: str | None
    hops: list[ServerHop] = field(default_factory=list)
    originating_ip: str | None = None
    geo: GeoResult | None = None
    auth: AuthResult = field(default_factory=AuthResult)
    reply_to_mismatch: bool = False
    is_bulk: bool = False
    flags: list[str] = field(default_factory=list)
    raw_headers: str | None = None


@dataclass
class ScanSummary:
    total_messages: int
    date_range: tuple[datetime, datetime]
    top_locations: list[tuple[str, int]] = field(default_factory=list)
    timezone_distribution: dict[str, int] = field(default_factory=dict)
    client_breakdown: dict[str, int] = field(default_factory=dict)
    flagged_messages: list[EmailAnalysis] = field(default_factory=list)
    emails: list[EmailAnalysis] = field(default_factory=list)


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
    signal: str
    confidence: float
    reasoning: str
    category: str


@dataclass
class DomainEntityMap:
    domain: str
    entity_id: str | None
    entity_name: str
    sector: str | None
    source: str


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
