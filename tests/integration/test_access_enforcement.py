"""An approved grant adds a live gate and cannot replace normal ABAC checks."""

import json
from datetime import datetime, timedelta

import pytest

from app.gateway.security import decode_token, issue_token

pytest_plugins = ["tests.integration.test_gateway"]


def add_identity(gateway, name, role, department, clearance):
    client, headers, _, path, config = gateway
    registry = json.loads(path.read_text())
    registry["accounts"][name] = {
        **registry["accounts"]["analyst"],
        "subject": {
            "id": name,
            "tenant_id": "demo",
            "role": role,
            "department": department,
            "clearance": clearance,
        },
    }
    path.write_text(json.dumps(registry))
    token = issue_token(name, config["secret"], 1, "A1")
    client.app.state.sessions.add(decode_token(token, config["secret"]))
    return {**headers, "authorization": "Bearer " + token}


def submit_and_approve(client, requester, owner, seconds=900):
    created = client.post(
        "/api/v1/access-requests",
        headers=requester,
        json={
            "resource": "production",
            "purpose": "Review production operational records",
            "duration_seconds": seconds,
        },
    )
    assert created.status_code == 201
    path = "/api/v1/access-requests/" + created.json()["request_id"]
    approved = client.post(path + "/approve", headers=owner)
    assert approved.status_code == 200 and approved.json()["status"] == "APPROVED"
    return path, approved.json()


def test_approval_and_revocation_are_additional_live_gates(gateway):
    client, _, db, *_ = gateway
    client.app.state.grant_required = frozenset({"production"})
    engineer = add_identity(gateway, "engineer", "data_engineer", "data", "restricted")
    owner = add_identity(gateway, "owner", "admin", "data", "restricted")
    denied = client.get("/api/v1/data/production", headers=engineer)
    assert denied.status_code == 403
    assert denied.json()["reason_code"] == "ACCESS_APPROVAL_REQUIRED"
    assert denied.json()["db_queried"] is False and not db.calls

    path, grant = submit_and_approve(client, engineer, owner)
    allowed = client.get("/api/v1/data/production", headers=engineer)
    assert allowed.status_code == 200 and allowed.json()["decision"] == "ALLOW"
    assert allowed.json()["access_request_id"] == grant["request_id"]
    assert len(db.calls) == 1
    assert db.calls[0].tenant_id == "demo"
    assert db.calls[0].row_scope.model_dump() == {"kind": "department", "value": "data"}

    revoked = client.post(path + "/revoke", headers=owner)
    assert revoked.status_code == 200 and revoked.json()["status"] == "REVOKED"
    denied = client.get("/api/v1/data/production", headers=engineer)
    assert denied.status_code == 403
    assert denied.json()["reason_code"] == "ACCESS_APPROVAL_REQUIRED"
    assert denied.json()["db_queried"] is False and len(db.calls) == 1


def test_approved_analyst_cannot_bypass_department_or_clearance_deny(gateway):
    client, analyst, db, *_ = gateway
    client.app.state.grant_required = frozenset({"production"})
    owner = add_identity(gateway, "owner", "admin", "data", "restricted")
    submit_and_approve(client, analyst, owner)
    denied = client.get("/api/v1/data/production", headers=analyst)
    assert denied.status_code == 403
    assert denied.json()["decision"] == "DENY"
    assert denied.json()["reason_code"] in {"DEPARTMENT_MISMATCH", "INSUFFICIENT_CLEARANCE"}
    assert denied.json()["db_queried"] is False and not db.calls


def test_expired_grant_denies_before_another_protected_select(gateway):
    client, _, db, *_ = gateway
    client.app.state.grant_required = frozenset({"production"})
    engineer = add_identity(gateway, "engineer", "data_engineer", "data", "restricted")
    owner = add_identity(gateway, "owner", "admin", "data", "restricted")
    _, grant = submit_and_approve(client, engineer, owner, seconds=60)
    expiry = datetime.fromisoformat(grant["expires_at"])
    client.app.state.access.clock = lambda: expiry - timedelta(seconds=1)
    assert client.get("/api/v1/data/production", headers=engineer).status_code == 200
    client.app.state.access.clock = lambda: expiry
    denied = client.get("/api/v1/data/production", headers=engineer)
    assert denied.status_code == 403
    assert denied.json()["reason_code"] == "ACCESS_APPROVAL_REQUIRED"
    assert denied.json()["db_queried"] is False and len(db.calls) == 1


@pytest.mark.parametrize("store,field", [("sessions", "session_ready"), ("access", "access_ready")])
@pytest.mark.parametrize("raises", [False, True])
def test_readiness_observes_state_store_failure(gateway, monkeypatch, store, field, raises):
    client, headers, db, *_ = gateway

    def unavailable():
        if raises:
            raise RuntimeError("State store unavailable")
        return False

    monkeypatch.setattr(getattr(client.app.state, store), "ready", unavailable)
    response = client.get("/health", headers=headers)
    assert response.status_code == 503 and response.json()[field] is False
    assert not db.calls
