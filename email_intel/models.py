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


@dataclass
class ScanSummary:
    total_messages: int
    date_range: tuple[datetime, datetime]
    top_locations: list[tuple[str, int]] = field(default_factory=list)
    timezone_distribution: dict[str, int] = field(default_factory=dict)
    client_breakdown: dict[str, int] = field(default_factory=dict)
    flagged_messages: list[EmailAnalysis] = field(default_factory=list)
    emails: list[EmailAnalysis] = field(default_factory=list)
