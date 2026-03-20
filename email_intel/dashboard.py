from __future__ import annotations
import json
import logging
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from email_intel.org_store import OrgStore

logger = logging.getLogger(__name__)

_HTML_PATH = Path(__file__).parent / "dashboard.html"


def _profile_to_dict(profile) -> dict:
    s = profile.current_stack
    return {
        "domain": profile.domain,
        "display_name": profile.display_name or profile.domain,
        "entity_id": profile.entity_id,
        "sector": profile.sector,
        "entity_source": profile.entity_source,
        "first_seen": profile.first_seen.isoformat(),
        "last_seen": profile.last_seen.isoformat(),
        "email_count": profile.email_count,
        "stack": {
            "mta_vendor": s.mta_vendor,
            "mta_version": s.mta_version,
            "email_platform": s.email_platform,
            "security_gateway": s.security_gateway,
            "security_gateway_version": s.security_gateway_version,
            "tls_version": s.tls_version,
            "tls_cipher": s.tls_cipher,
            "dmarc_policy": s.dmarc_policy,
            "spf_result": s.spf_result,
            "dkim_domains": s.dkim_domains,
            "dlp_system": s.dlp_system,
            "tenant_id": s.tenant_id,
        },
    }


class DashboardHandler(BaseHTTPRequestHandler):
    store: OrgStore

    def log_message(self, format, *args):
        logger.debug(format, *args)

    def _json_response(self, data, status=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html_response(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, message):
        self._json_response({"error": message}, status)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)

        try:
            if path == "/":
                self._handle_root()
            elif path == "/api/orgs":
                self._handle_orgs()
            elif path.startswith("/api/orgs/"):
                domain = path[len("/api/orgs/"):]
                self._handle_org_detail(domain)
            elif path == "/api/changes":
                self._handle_changes(params)
            elif path == "/api/stats":
                self._handle_stats()
            else:
                self._error(404, "Not found")
        except Exception as e:
            logger.error("Server error: %s", e)
            self._error(500, str(e))

    def _handle_root(self):
        if _HTML_PATH.exists():
            html = _HTML_PATH.read_text(encoding="utf-8")
        else:
            html = "<!DOCTYPE html><html><body><h1>dashboard.html not found</h1></body></html>"
        self._html_response(html)

    def _handle_orgs(self):
        profiles = self.store.list_profiles()
        self._json_response([_profile_to_dict(p) for p in profiles])

    def _handle_org_detail(self, domain: str):
        profile = self.store.get_profile(domain)
        entity = self.store.resolve_entity(domain)
        if not profile and not entity:
            self._error(404, f"No profile found for {domain}")
            return
        changes = self.store.get_changes_with_classification(domain=domain)
        self._json_response({
            "profile": _profile_to_dict(profile) if profile else None,
            "changes": changes,
            "entity": {
                "entity_name": entity.entity_name,
                "sector": entity.sector,
                "source": entity.source,
            } if entity else None,
        })

    def _handle_changes(self, params: dict):
        days = int(params.get("days", [0])[0]) or None
        signal = params.get("signal", [None])[0]
        domain = params.get("domain", [None])[0]
        changes = self.store.get_changes_with_classification(
            domain=domain, days=days, signal=signal,
        )
        self._json_response(changes)

    def _handle_stats(self):
        profiles = self.store.list_profiles()
        platform_counter: Counter[str] = Counter()
        gateway_counter: Counter[str] = Counter()
        dmarc_counter: Counter[str] = Counter()
        last_seen = None

        for p in profiles:
            s = p.current_stack
            platform_counter[s.email_platform or "other"] += 1
            if s.security_gateway:
                gateway_counter[s.security_gateway] += 1
            dmarc_counter[s.dmarc_policy or "unknown"] += 1
            if last_seen is None or p.last_seen > last_seen:
                last_seen = p.last_seen

        all_changes = self.store.get_changes_with_classification()
        changes_7d = self.store.get_changes_with_classification(days=7)

        self._json_response({
            "total_orgs": len(profiles),
            "platform_breakdown": dict(platform_counter),
            "security_gateways": dict(gateway_counter),
            "dmarc_breakdown": dict(dmarc_counter),
            "total_changes": len(all_changes),
            "changes_7d": len(changes_7d),
            "last_scan": last_seen.isoformat() if last_seen else None,
        })


def create_server(store: OrgStore, port: int = 8888) -> HTTPServer:
    DashboardHandler.store = store
    server = HTTPServer(("localhost", port), DashboardHandler)
    return server
