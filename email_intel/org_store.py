from __future__ import annotations
import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from email_intel.models import DomainEntityMap, InfraStack, OrgProfile, StackChange

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path.home() / ".email-intel" / "orgs.db"

_TRACKED_FIELDS = [
    "mta_vendor", "mta_version", "email_platform",
    "security_gateway", "security_gateway_version",
    "tls_version", "tls_cipher", "dmarc_policy", "spf_result",
    "dlp_system", "tenant_id",
]


class OrgStore:
    def __init__(self, db_path: str | None = None):
        self._db_path = db_path or str(_DEFAULT_DB)
        parent = Path(self._db_path).parent
        parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            try:
                os.chmod(str(parent), 0o700)
            except OSError:
                pass
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def _init_db(self):
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS org_profiles (
                domain TEXT PRIMARY KEY,
                display_name TEXT,
                entity_id TEXT,
                sector TEXT,
                entity_source TEXT DEFAULT 'inferred',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                email_count INTEGER DEFAULT 0,
                current_stack TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stack_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                field TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                signal TEXT,
                confidence REAL,
                reasoning TEXT,
                category TEXT,
                FOREIGN KEY (domain) REFERENCES org_profiles(domain)
            );
            CREATE INDEX IF NOT EXISTS idx_stack_changes_domain ON stack_changes(domain);
            CREATE INDEX IF NOT EXISTS idx_stack_changes_timestamp ON stack_changes(timestamp);
            CREATE TABLE IF NOT EXISTS domain_entity_map (
                domain TEXT PRIMARY KEY,
                entity_id TEXT,
                entity_name TEXT NOT NULL,
                sector TEXT,
                source TEXT DEFAULT 'manual'
            );
        """)
        conn.commit()
        conn.close()

    def upsert(self, domain: str, stack: InfraStack) -> list[StackChange]:
        conn = self._conn()
        now = datetime.now(tz=timezone.utc).isoformat()
        stack_json = stack.to_json()

        row = conn.execute("SELECT * FROM org_profiles WHERE domain = ?", (domain,)).fetchone()

        if row is None:
            conn.execute(
                "INSERT INTO org_profiles (domain, display_name, first_seen, last_seen, email_count, current_stack) VALUES (?, ?, ?, ?, 1, ?)",
                (domain, domain, now, now, stack_json),
            )
            conn.commit()
            conn.close()
            return []

        old_stack = InfraStack.from_json(row["current_stack"])
        changes: list[StackChange] = []

        for field in _TRACKED_FIELDS:
            old_val = getattr(old_stack, field)
            new_val = getattr(stack, field)
            old_str = str(old_val) if old_val is not None else None
            new_str = str(new_val) if new_val is not None else None
            if old_str != new_str:
                cursor = conn.execute(
                    "INSERT INTO stack_changes (domain, timestamp, field, old_value, new_value) VALUES (?, ?, ?, ?, ?)",
                    (domain, now, field, old_str, new_str),
                )
                changes.append(StackChange(
                    id=cursor.lastrowid, domain=domain,
                    timestamp=datetime.fromisoformat(now),
                    field=field, old_value=old_str, new_value=new_str,
                ))

        old_dkim = sorted(old_stack.dkim_domains)
        new_dkim = sorted(stack.dkim_domains)
        if old_dkim != new_dkim:
            cursor = conn.execute(
                "INSERT INTO stack_changes (domain, timestamp, field, old_value, new_value) VALUES (?, ?, ?, ?, ?)",
                (domain, now, "dkim_domains", ",".join(old_dkim), ",".join(new_dkim)),
            )
            changes.append(StackChange(
                id=cursor.lastrowid, domain=domain,
                timestamp=datetime.fromisoformat(now),
                field="dkim_domains", old_value=",".join(old_dkim), new_value=",".join(new_dkim),
            ))

        conn.execute(
            "UPDATE org_profiles SET last_seen = ?, email_count = email_count + 1, current_stack = ? WHERE domain = ?",
            (now, stack_json, domain),
        )
        conn.commit()
        conn.close()
        return changes

    def classify_change(self, change_id: int, signal: str, confidence: float, reasoning: str, category: str):
        conn = self._conn()
        conn.execute(
            "UPDATE stack_changes SET signal = ?, confidence = ?, reasoning = ?, category = ? WHERE id = ?",
            (signal, confidence, reasoning, category, change_id),
        )
        conn.commit()
        conn.close()

    def get_profile(self, domain: str) -> OrgProfile | None:
        conn = self._conn()
        row = conn.execute("SELECT * FROM org_profiles WHERE domain = ?", (domain,)).fetchone()
        conn.close()
        if not row:
            return None
        return self._row_to_profile(row)

    def list_profiles(self) -> list[OrgProfile]:
        conn = self._conn()
        rows = conn.execute("SELECT * FROM org_profiles ORDER BY last_seen DESC").fetchall()
        conn.close()
        return [self._row_to_profile(r) for r in rows]

    def get_changes(self, domain: str | None = None, days: int | None = None, signal: str | None = None) -> list[StackChange]:
        conn = self._conn()
        query = "SELECT * FROM stack_changes WHERE 1=1"
        params: list = []
        if domain:
            query += " AND domain = ?"
            params.append(domain)
        if days:
            cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=days)).isoformat()
            query += " AND timestamp >= ?"
            params.append(cutoff)
        if signal:
            query += " AND signal = ?"
            params.append(signal)
        query += " ORDER BY timestamp DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [
            StackChange(id=r["id"], domain=r["domain"],
                timestamp=datetime.fromisoformat(r["timestamp"]),
                field=r["field"], old_value=r["old_value"], new_value=r["new_value"])
            for r in rows
        ]

    def _get_change_row(self, change_id: int) -> sqlite3.Row | None:
        conn = self._conn()
        row = conn.execute("SELECT * FROM stack_changes WHERE id = ?", (change_id,)).fetchone()
        conn.close()
        return row

    def set_entity_mapping(self, domain: str, entity_name: str, entity_id: str | None = None, sector: str | None = None, source: str = "manual"):
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO domain_entity_map (domain, entity_id, entity_name, sector, source) VALUES (?, ?, ?, ?, ?)",
            (domain, entity_id, entity_name, sector, source),
        )
        conn.execute(
            "UPDATE org_profiles SET display_name = ?, entity_id = ?, sector = ?, entity_source = ? WHERE domain = ?",
            (entity_name, entity_id, sector, source, domain),
        )
        conn.commit()
        conn.close()

    def resolve_entity(self, domain: str) -> DomainEntityMap | None:
        conn = self._conn()
        row = conn.execute("SELECT * FROM domain_entity_map WHERE domain = ?", (domain,)).fetchone()
        conn.close()
        if not row:
            return None
        return DomainEntityMap(domain=row["domain"], entity_id=row["entity_id"],
            entity_name=row["entity_name"], sector=row["sector"], source=row["source"])

    def _row_to_profile(self, row: sqlite3.Row) -> OrgProfile:
        return OrgProfile(
            domain=row["domain"], display_name=row["display_name"],
            entity_id=row["entity_id"], sector=row["sector"],
            entity_source=row["entity_source"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            email_count=row["email_count"],
            current_stack=InfraStack.from_json(row["current_stack"]),
        )
