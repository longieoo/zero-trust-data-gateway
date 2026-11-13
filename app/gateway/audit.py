"""Encrypted durable audit: intent before SELECT, response before HTTP delivery.

Crash between events leaves an incomplete request. SQLite/WAL is single-host.
"""

import base64
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.gateway.releases import canonical


def actor_hash(subject):
    return hashlib.sha256(subject.encode()).hexdigest()


class AuditStore:
    def __init__(self, path, key):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.cipher = AESGCM(bytes.fromhex(key))
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL, phase TEXT NOT NULL, tenant TEXT,
                actor TEXT, recorded_at TEXT NOT NULL, metadata TEXT NOT NULL,
                snapshot TEXT, UNIQUE(request_id, phase))""")
            db.execute("CREATE INDEX IF NOT EXISTS audit_tenant ON audit(tenant, sequence)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS audit_health (id INTEGER PRIMARY KEY, probe INTEGER)"
            )

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    def append(self, request_id, phase, metadata, snapshot=None, tenant=None, subject=None):
        if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
            raise ValueError("Invalid audit request identifier")
        if phase not in {"received", "intent", "response"} or not isinstance(metadata, dict):
            raise ValueError("Invalid audit event contract")
        if snapshot is not None and phase != "intent":
            raise ValueError("Replay snapshots belong to intent events")
        encoded = canonical(metadata).decode()
        if len(encoded.encode()) > 64_000:
            raise ValueError("Oversized audit metadata")
        actor = actor_hash(subject) if subject else None
        aad = canonical([request_id, phase, tenant, actor, metadata])
        sealed = None
        if snapshot is not None:
            plaintext = canonical(snapshot)
            if len(plaintext) > 8_000_000:
                raise ValueError("Oversized replay snapshot")
            nonce = os.urandom(12)
            sealed = base64.b64encode(nonce + self.cipher.encrypt(nonce, plaintext, aad)).decode()
        with self.connect() as db:
            db.execute(
                "INSERT INTO audit(request_id,phase,tenant,actor,recorded_at,metadata,snapshot) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    request_id,
                    phase,
                    tenant,
                    actor,
                    datetime.now(timezone.utc).isoformat(),
                    encoded,
                    sealed,
                ),
            )

    def list(self, tenant, subject=None, before=2**63 - 1, limit=50):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Audit page size must be 1..100")
        if type(before) is not int or not 1 <= before <= 2**63 - 1:
            raise ValueError("Invalid audit cursor")
        actor = actor_hash(subject) if subject else None
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM audit WHERE tenant=? AND sequence<? AND phase='response' "
                "AND (? IS NULL OR actor=?) ORDER BY sequence DESC LIMIT ?",
                (tenant, before, actor, actor, limit),
            ).fetchall()
        return [
            {
                **{key: row[key] for key in ("sequence", "request_id", "recorded_at", "phase")},
                **json.loads(row["metadata"]),
            }
            for row in rows
        ]

    def snapshot(self, request_id, tenant, subject=None):
        actor = actor_hash(subject) if subject else None
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM audit WHERE request_id=? AND tenant=? AND phase='intent' "
                "AND (? IS NULL OR actor=?)",
                (request_id, tenant, actor, actor),
            ).fetchone()
        if row is None or row["snapshot"] is None:
            return None
        if len(row["snapshot"]) > 11_000_000:
            raise ValueError("Oversized stored snapshot")
        raw = base64.b64decode(row["snapshot"], validate=True)
        if len(raw) < 28:
            raise ValueError("Invalid stored snapshot")
        aad = canonical(
            [request_id, row["phase"], tenant, row["actor"], json.loads(row["metadata"])]
        )
        return json.loads(self.cipher.decrypt(raw[:12], raw[12:], aad))

    def backup(self, destination):
        with self.connect() as source, sqlite3.connect(destination) as target:
            source.backup(target)

    def ready(self):
        # A readable SQLite file may still be unwritable (permissions, a full
        # volume, or another writer holding a lock). Exercise the actual write
        # path without leaving fake security events in the audit timeline.
        try:
            with self.connect() as db:
                if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    return False
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT OR REPLACE INTO audit_health VALUES (1, 1)")
                db.rollback()
                return True
        except sqlite3.Error:
            return False
