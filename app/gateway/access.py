"""Tenant-scoped access requests and short-lived, explicitly approved grants.

A grant is an additional gate, never a replacement for ABAC, device validation,
tenant RLS or column masking. The caller must still evaluate its normal policy.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import HTTPException, Request
from pydantic import Field, field_validator

from app.models import StrictModel

RESOURCES = {"customers", "financial", "production"}
MAX_PENDING_AGE = 86400


class AccessProposal(StrictModel):
    resource: Literal["customers", "financial", "production"]
    purpose: str = Field(min_length=10, max_length=500)
    duration_seconds: int = Field(default=900, ge=60, le=3600)

    @field_validator("purpose")
    @classmethod
    def valid_purpose(cls, value):
        value = value.strip()
        if len(value) < 10 or any(ord(char) < 32 for char in value):
            raise ValueError("Provide a single-line purpose of at least ten characters")
        return value


def utc_now():
    return datetime.now(timezone.utc)


def identity_scope(subject):
    """Invalidate old grants when the requester's authorization attributes change."""
    return json.dumps(
        {key: subject[key] for key in ("id", "tenant_id", "role", "department", "clearance")},
        sort_keys=True,
        separators=(",", ":"),
    )


class AccessStore:
    def __init__(self, path, clock=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock or utc_now
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS access_requests (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                requester TEXT NOT NULL,
                requester_scope TEXT NOT NULL,
                resource TEXT NOT NULL,
                purpose TEXT NOT NULL,
                duration_seconds INTEGER NOT NULL CHECK(duration_seconds BETWEEN 60 AND 3600),
                status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','REVOKED')),
                created_at INTEGER NOT NULL,
                approved_at INTEGER,
                expires_at INTEGER,
                approver TEXT,
                revoked_at INTEGER,
                revoked_by TEXT)""")
            db.execute(
                "CREATE INDEX IF NOT EXISTS access_tenant ON access_requests(tenant_id, sequence)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS access_active ON access_requests(tenant_id, requester, resource, expires_at)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS access_health (id INTEGER PRIMARY KEY CHECK(id=1))"
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

    def now(self):
        value = self.clock()
        if not isinstance(value, datetime) or value.utcoffset() is None:
            raise ValueError("Access workflow requires a timezone-aware clock")
        return int(value.timestamp())

    @staticmethod
    def record(row, now):
        value = dict(row)
        value.pop("requester_scope", None)
        if value["status"] == "APPROVED" and value["expires_at"] <= now:
            value["status"] = "EXPIRED"
        if value["status"] == "PENDING" and value["created_at"] + MAX_PENDING_AGE <= now:
            value["status"] = "EXPIRED"
        for key in ("created_at", "approved_at", "expires_at", "revoked_at"):
            if value[key] is not None:
                value[key] = datetime.fromtimestamp(value[key], timezone.utc).isoformat()
        return value

    def create(self, subject, resource, purpose, duration_seconds=900):
        proposal = AccessProposal(
            resource=resource, purpose=purpose, duration_seconds=duration_seconds
        )
        now = self.now()
        request_id = str(uuid4())
        scope = identity_scope(subject)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Bound queue and storage rather than silently deleting governance history.
            if db.execute("SELECT count(*) FROM access_requests").fetchone()[0] >= 50000:
                raise HTTPException(503, "Access request capacity reached")
            count = db.execute(
                "SELECT count(*) FROM access_requests WHERE tenant_id=? AND requester=? "
                "AND status='PENDING' AND created_at>?",
                (subject["tenant_id"], subject["id"], now - MAX_PENDING_AGE),
            ).fetchone()[0]
            if count >= 10:
                raise HTTPException(429, "Too many pending access requests")
            duplicate = db.execute(
                "SELECT 1 FROM access_requests WHERE tenant_id=? AND requester=? AND resource=? "
                "AND requester_scope=? AND ((status='PENDING' AND created_at>?) "
                "OR (status='APPROVED' AND expires_at>?))",
                (subject["tenant_id"], subject["id"], resource, scope, now - MAX_PENDING_AGE, now),
            ).fetchone()
            if duplicate:
                raise HTTPException(409, "An active or pending request already exists")
            db.execute(
                "INSERT INTO access_requests(request_id,tenant_id,requester,requester_scope,resource,"
                "purpose,duration_seconds,status,created_at) VALUES (?,?,?,?,?,?,?,'PENDING',?)",
                (
                    request_id,
                    subject["tenant_id"],
                    subject["id"],
                    scope,
                    resource,
                    proposal.purpose,
                    proposal.duration_seconds,
                    now,
                ),
            )
            row = db.execute(
                "SELECT * FROM access_requests WHERE request_id=?", (request_id,)
            ).fetchone()
        return self.record(row, now)

    @staticmethod
    def require_admin(subject):
        if subject["role"] != "admin":
            raise HTTPException(403, "Tenant admin required")

    def list(self, subject, before=2**63 - 1, limit=20):
        if (
            type(before) is not int
            or type(limit) is not int
            or not 1 <= before <= 2**63 - 1
            or not 1 <= limit <= 100
        ):
            raise HTTPException(422, "Invalid pagination")
        actor = None if subject["role"] == "admin" else subject["id"]
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM access_requests WHERE tenant_id=? AND sequence<? "
                "AND (? IS NULL OR requester=?) ORDER BY sequence DESC LIMIT ?",
                (subject["tenant_id"], before, actor, actor, limit),
            ).fetchall()
        now = self.now()
        return [self.record(row, now) for row in rows]

    def approve(self, subject, request_id):
        self.require_admin(subject)
        now = self.now()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM access_requests WHERE request_id=? AND tenant_id=?",
                (request_id, subject["tenant_id"]),
            ).fetchone()
            if row is None:
                raise HTTPException(404, "Access request not found")
            if row["requester"] == subject["id"]:
                raise HTTPException(403, "Self approval is forbidden")
            if row["status"] != "PENDING" or row["created_at"] + MAX_PENDING_AGE <= now:
                raise HTTPException(409, "Request is no longer pending")
            db.execute(
                "UPDATE access_requests SET status='APPROVED',approver=?,approved_at=?,expires_at=? "
                "WHERE request_id=? AND tenant_id=?",
                (
                    subject["id"],
                    now,
                    now + row["duration_seconds"],
                    request_id,
                    subject["tenant_id"],
                ),
            )
            row = db.execute(
                "SELECT * FROM access_requests WHERE request_id=?", (request_id,)
            ).fetchone()
        return self.record(row, now)

    def revoke(self, subject, request_id):
        self.require_admin(subject)
        now = self.now()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM access_requests WHERE request_id=? AND tenant_id=?",
                (request_id, subject["tenant_id"]),
            ).fetchone()
            if row is None:
                raise HTTPException(404, "Access request not found")
            if row["status"] != "REVOKED":
                db.execute(
                    "UPDATE access_requests SET status='REVOKED',revoked_at=?,revoked_by=? "
                    "WHERE request_id=? AND tenant_id=?",
                    (now, subject["id"], request_id, subject["tenant_id"]),
                )
            row = db.execute(
                "SELECT * FROM access_requests WHERE request_id=?", (request_id,)
            ).fetchone()
        return self.record(row, now)

    def active_grant(self, subject, resource):
        if resource not in RESOURCES:
            return None
        now = self.now()
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM access_requests WHERE tenant_id=? AND requester=? AND resource=? "
                "AND requester_scope=? AND status='APPROVED' AND expires_at>? AND approved_at<=? "
                "ORDER BY sequence DESC LIMIT 1",
                (subject["tenant_id"], subject["id"], resource, identity_scope(subject), now, now),
            ).fetchone()
        return self.record(row, now) if row else None

    def ready(self):
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT OR REPLACE INTO access_health(id) VALUES (1)")
                db.rollback()
                return True
        except sqlite3.Error:
            return False


def attach_access_routes(app, identity_callable, store, clock=None):
    """Mount workflow routes using the Gateway's verified identity dependency.

    Pass the same clock to AccessStore for deterministic tests. ``clock`` is
    accepted as an integration convenience; it must match the store's clock.
    """
    if clock is not None:
        store.clock = clock

    def workflow_event(request, event, request_id):
        if hasattr(request.state, "event"):
            request.state.event.update(workflow_event=event, access_request_id=request_id)

    @app.post("/api/v1/access-requests", status_code=201)
    def create_access_request(body: AccessProposal, request: Request):
        subject = identity_callable(request)
        record = store.create(subject, body.resource, body.purpose, body.duration_seconds)
        workflow_event(request, "access_requested", record["request_id"])
        return record

    @app.get("/api/v1/access-requests")
    def access_request_list(request: Request, before: int = 2**63 - 1, limit: int = 20):
        subject = identity_callable(request)
        rows = store.list(subject, before, limit)
        return {
            "requests": rows,
            "tenant_id": subject["tenant_id"],
            "next_cursor": rows[-1]["sequence"] if rows else None,
        }

    @app.post("/api/v1/access-requests/{request_id}/approve")
    def approve_access_request(request_id: str, request: Request):
        subject = identity_callable(request)
        record = store.approve(subject, request_id)
        workflow_event(request, "access_approved", request_id)
        return record

    @app.post("/api/v1/access-requests/{request_id}/revoke")
    def revoke_access_request(request_id: str, request: Request):
        subject = identity_callable(request)
        record = store.revoke(subject, request_id)
        workflow_event(request, "access_revoked", request_id)
        return record
