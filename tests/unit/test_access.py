"""Approval is a tenant-scoped additional gate with bounded, live-checked expiry."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import sqlite3

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from app.gateway.access import AccessProposal, AccessStore, attach_access_routes


def subject(name="analyst", tenant="demo", role="marketing_analyst"):
    return {
        "id": name,
        "tenant_id": tenant,
        "role": role,
        "department": "marketing",
        "clearance": "confidential",
    }


@pytest.fixture
def workflow(tmp_path):
    clock = [datetime(2026, 11, 13, 8, tzinfo=timezone.utc)]
    store = AccessStore(tmp_path / "access.sqlite", clock=lambda: clock[0])
    return store, clock


def create(store, actor=None, resource="customers", seconds=900):
    return store.create(actor or subject(), resource, "Quarterly customer analysis", seconds)


def test_request_does_not_itself_grant_access(workflow):
    store, _ = workflow
    row = create(store)
    assert row["status"] == "PENDING" and row["approver"] is None
    assert store.active_grant(subject(), "customers") is None
    assert store.ready()


def test_readiness_write_probe_rolls_back_without_changing_business_rows(workflow):
    store, _ = workflow
    row = create(store)
    for _ in range(3):
        assert store.ready()
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM access_health").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM access_requests").fetchone()[0] == 1
    assert store.list(subject())[0]["request_id"] == row["request_id"]


def test_readonly_access_store_is_not_ready(workflow, monkeypatch):
    store, _ = workflow

    @contextmanager
    def readonly():
        db = sqlite3.connect(store.path.as_uri() + "?mode=ro", uri=True)
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(store, "connect", readonly)
    assert store.ready() is False


def test_approval_expiry_is_measured_from_approval_and_checked_live(workflow):
    store, clock = workflow
    row = create(store, seconds=60)
    clock[0] += timedelta(minutes=10)
    approved = store.approve(subject("admin", role="admin"), row["request_id"])
    assert approved["status"] == "APPROVED"
    assert approved["expires_at"] == (clock[0] + timedelta(seconds=60)).isoformat()
    assert store.active_grant(subject(), "customers")
    clock[0] += timedelta(seconds=60)
    assert store.active_grant(subject(), "customers") is None
    assert store.list(subject())[0]["status"] == "EXPIRED"


def test_expired_pending_request_cannot_be_approved(workflow):
    store, clock = workflow
    row = create(store)
    clock[0] += timedelta(days=1)
    with pytest.raises(HTTPException) as caught:
        store.approve(subject("admin", role="admin"), row["request_id"])
    assert caught.value.status_code == 409
    assert store.list(subject())[0]["status"] == "EXPIRED"
    assert create(store)["request_id"] != row["request_id"]


@pytest.mark.parametrize("action", ["approve", "revoke"])
def test_non_admin_cannot_manage_requests(workflow, action):
    store, _ = workflow
    row = create(store)
    with pytest.raises(HTTPException) as caught:
        getattr(store, action)(subject("other"), row["request_id"])
    assert caught.value.status_code == 403


def test_admin_cannot_approve_own_request(workflow):
    store, _ = workflow
    actor = subject("admin", role="admin")
    row = create(store, actor)
    with pytest.raises(HTTPException) as caught:
        store.approve(actor, row["request_id"])
    assert caught.value.status_code == 403
    assert store.active_grant(actor, "customers") is None


@pytest.mark.parametrize("action", ["approve", "revoke"])
def test_admin_cannot_touch_other_tenant_request(workflow, action):
    store, _ = workflow
    row = create(store)
    outsider = subject("admin", "beta", "admin")
    with pytest.raises(HTTPException) as caught:
        getattr(store, action)(outsider, row["request_id"])
    assert caught.value.status_code == 404
    assert store.list(outsider) == []


def test_request_list_is_private_and_pagination_stable(workflow):
    store, _ = workflow
    first = create(store)
    second = create(store, subject("colleague"))
    third = create(store, subject("another"))
    assert [r["request_id"] for r in store.list(subject())] == [first["request_id"]]
    admin = subject("admin", role="admin")
    page = store.list(admin, limit=2)
    assert [r["request_id"] for r in page] == [third["request_id"], second["request_id"]]
    assert store.list(admin, before=page[-1]["sequence"])[0]["request_id"] == first["request_id"]
    assert all("requester_scope" not in r for r in page)


def test_grant_is_bound_to_identity_tenant_resource_and_authorization_attributes(workflow):
    store, _ = workflow
    row = create(store)
    store.approve(subject("admin", role="admin"), row["request_id"])
    assert store.active_grant(subject(), "customers")
    assert store.active_grant(subject(), "financial") is None
    assert store.active_grant(subject("someone-else"), "customers") is None
    assert store.active_grant(subject(tenant="beta"), "customers") is None
    for field, changed in (
        ("department", "finance"),
        ("role", "admin"),
        ("clearance", "restricted"),
    ):
        assert store.active_grant({**subject(), field: changed}, "customers") is None


def test_revoke_takes_effect_without_cache_and_is_idempotent(workflow):
    store, _ = workflow
    row = create(store)
    admin = subject("admin", role="admin")
    store.approve(admin, row["request_id"])
    assert store.active_grant(subject(), "customers")
    record = store.revoke(admin, row["request_id"])
    assert record["status"] == "REVOKED"
    assert store.active_grant(subject(), "customers") is None
    assert store.revoke(subject("second-admin", role="admin"), row["request_id"]) == record


def test_grants_survive_store_recreation(workflow):
    store, clock = workflow
    row = create(store)
    store.approve(subject("admin", role="admin"), row["request_id"])
    reopened = AccessStore(store.path, lambda: clock[0])
    assert reopened.active_grant(subject(), "customers")["request_id"] == row["request_id"]


def test_concurrent_approvals_have_only_one_winner(workflow):
    store, _ = workflow
    row = create(store)

    def approve(name):
        try:
            return store.approve(subject(name, role="admin"), row["request_id"])["approver"]
        except HTTPException as exc:
            return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(approve, ["admin-a", "admin-b"]))
    assert result.count(409) == 1
    assert store.active_grant(subject(), "customers")["approver"] in {"admin-a", "admin-b"}


def test_duplicate_pending_request_rejected_atomically(workflow):
    store, _ = workflow

    def submit(_):
        try:
            return create(store)["status"]
        except HTTPException as exc:
            return exc.status_code

    with ThreadPoolExecutor(max_workers=4) as pool:
        result = list(pool.map(submit, range(4)))
    assert result.count("PENDING") == 1 and result.count(409) == 3


@pytest.mark.parametrize(
    "mutation",
    [
        {"purpose": "         "},
        {"purpose": "analysis\nwith newline"},
        {"purpose": "x" * 501},
        {"duration_seconds": 59},
        {"duration_seconds": 3601},
        {"duration_seconds": True},
        {"duration_seconds": "900"},
        {"resource": "unknown"},
        {"requester": "admin"},
        {"tenant_id": "beta"},
    ],
)
def test_request_contract_rejects_invalid_or_spoofed_fields(mutation):
    body = {
        "resource": "customers",
        "purpose": "Quarterly customer analysis",
        "duration_seconds": 900,
    }
    with pytest.raises(ValueError):
        AccessProposal.model_validate({**body, **mutation})


@pytest.mark.parametrize(
    "params", [{"before": 0}, {"before": 2**64}, {"limit": 0}, {"limit": 101}, {"limit": True}]
)
def test_store_bounds_pagination(workflow, params):
    with pytest.raises(HTTPException) as caught:
        workflow[0].list(subject(), **params)
    assert caught.value.status_code == 422


def test_routes_take_identity_only_from_verified_callback(workflow):
    store, _ = workflow
    app = FastAPI()
    identities = {
        "analyst": subject(),
        "admin": subject("admin", role="admin"),
        "outsider": subject("admin", "beta", "admin"),
    }

    def identity(request: Request):
        actor = request.headers.get("test-identity")
        if actor not in identities:
            raise HTTPException(401, "Identity required")
        return identities[actor]

    attach_access_routes(app, identity, store)
    with TestClient(app) as client:
        headers = {"test-identity": "analyst"}
        assert client.get("/api/v1/access-requests").status_code == 401
        result = client.post(
            "/api/v1/access-requests",
            headers=headers,
            json={"resource": "production", "purpose": "Review batch operational logs"},
        )
        assert result.status_code == 201
        row = result.json()
        assert row["requester"] == "analyst" and row["tenant_id"] == "demo"
        path = "/api/v1/access-requests/" + row["request_id"]
        assert client.post(path + "/approve", headers=headers).status_code == 403
        assert (
            client.post(path + "/approve", headers={"test-identity": "outsider"}).status_code == 404
        )
        assert (
            client.post(path + "/approve", headers={"test-identity": "admin"}).json()["status"]
            == "APPROVED"
        )
        assert client.get("/api/v1/access-requests?limit=0", headers=headers).status_code == 422
        assert (
            client.post(path + "/revoke", headers={"test-identity": "admin"}).json()["status"]
            == "REVOKED"
        )
