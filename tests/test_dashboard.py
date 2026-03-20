import json
import threading
import time
from datetime import datetime, timezone
from http.client import HTTPConnection
from email_intel.org_store import OrgStore
from email_intel.models import InfraStack
from email_intel.dashboard import create_server


def _make_stack(**overrides) -> InfraStack:
    defaults = dict(
        mta_vendor="Microsoft Exchange", mta_version="15.2.2562.37",
        email_platform="m365", security_gateway="Proofpoint",
        security_gateway_version="Hydra:6.1.51",
        tls_version="TLS1_2", tls_cipher="AES256",
        dmarc_policy="reject", spf_result="pass",
        dkim_domains=["gs.com"], dlp_system="Titus",
        dlp_metadata={"Aud": "UNR"}, tenant_id="abc-123",
        antispam_scores={"BCL": 0}, proofpoint_engines={"Hydra": "6.1.51"},
        observed_at=datetime(2026, 3, 19, 16, 0, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return InfraStack(**defaults)


class TestDashboardAPI:
    @classmethod
    def setup_class(cls):
        import tempfile
        cls.tmp_dir = tempfile.mkdtemp()
        db_path = f"{cls.tmp_dir}/test.db"
        cls.store = OrgStore(db_path=db_path)
        cls.store.upsert("gs.com", _make_stack())
        cls.store.upsert("google.com", _make_stack(
            mta_vendor="Google", email_platform="google-workspace",
            security_gateway=None, security_gateway_version=None,
            dmarc_policy="reject", dlp_system=None,
        ))
        stack2 = _make_stack(dmarc_policy="quarantine")
        cls.store.upsert("gs.com", stack2)
        changes = cls.store.get_changes(domain="gs.com")
        if changes:
            cls.store.classify_change(changes[0].id, "negative", 0.9, "DMARC weakened", "security")
        cls.store.set_entity_mapping("gs.com", "Goldman Sachs", sector="Finance")
        cls.server = create_server(cls.store, port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def teardown_class(cls):
        cls.server.shutdown()

    def _get(self, path):
        conn = HTTPConnection("localhost", self.port)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = json.loads(resp.read().decode())
        conn.close()
        return resp.status, body

    def test_api_orgs(self):
        status, data = self._get("/api/orgs")
        assert status == 200
        assert len(data) == 2
        domains = {d["domain"] for d in data}
        assert "gs.com" in domains
        gs = next(d for d in data if d["domain"] == "gs.com")
        assert gs["stack"]["mta_vendor"] == "Microsoft Exchange"

    def test_api_orgs_detail(self):
        status, data = self._get("/api/orgs/gs.com")
        assert status == 200
        assert data["profile"]["domain"] == "gs.com"
        assert len(data["changes"]) >= 1
        assert data["entity"]["entity_name"] == "Goldman Sachs"

    def test_api_orgs_detail_unknown(self):
        status, data = self._get("/api/orgs/unknown.example.com")
        assert status == 404

    def test_api_changes(self):
        status, data = self._get("/api/changes")
        assert status == 200
        assert len(data) >= 1
        assert "signal" in data[0]
        assert "reasoning" in data[0]

    def test_api_changes_filtered(self):
        status, data = self._get("/api/changes?signal=negative")
        assert status == 200
        for c in data:
            assert c["signal"] == "negative"

    def test_api_stats(self):
        status, data = self._get("/api/stats")
        assert status == 200
        assert data["total_orgs"] == 2
        assert "platform_breakdown" in data
        assert "dmarc_breakdown" in data

    def test_root_returns_html(self):
        conn = HTTPConnection("localhost", self.port)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        assert resp.status == 200
        assert "<!DOCTYPE html>" in body

    def test_404_unknown_path(self):
        status, data = self._get("/api/unknown")
        assert status == 404
