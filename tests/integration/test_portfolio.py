"""Portfolio invariants: real OPA, observable database boundary, durable audit."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from app.gateway.audit import AuditStore
from app.gateway.releases import engine_revision

pytest_plugins = ["tests.integration.test_gateway"]


def read(gateway):
    client, headers, *_ = gateway
    return client.get("/api/v1/data/customers", headers=headers)


def test_tenant_and_policy_revision_bound_to_enforcement(gateway):
    result = read(gateway).json()
    assert result["obligations"]["tenant_id"] == "demo"
    assert result["policy_revision"] == result["obligations"]["policy_revision"]
    assert gateway[2].calls[0].tenant_id == "demo"


def test_account_tenant_move_invalidates_existing_token(gateway):
    _, _, db, path, _ = gateway
    registry = json.loads(path.read_text())
    registry["accounts"]["analyst"]["subject"]["tenant_id"] = "beta"
    path.write_text(json.dumps(registry))
    assert read(gateway).status_code == 401
    assert not db.calls


def test_registry_missing_tenant_is_not_silently_defaulted(gateway):
    _, _, db, path, _ = gateway
    registry = json.loads(path.read_text())
    del registry["accounts"]["analyst"]["subject"]["tenant_id"]
    path.write_text(json.dumps(registry))
    assert read(gateway).status_code == 503
    assert not db.calls


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.update(revision="0" * 64),
        lambda r: r.update(engine_revision="0" * 64),
        lambda r: r["plan"].update(tenant_id="beta"),
        lambda r: r["plan"].update(policy_revision="0" * 64),
        lambda r: r["plan"].update(mask=[]),
        lambda r: r["plan"].update(row_scope={"kind": "all"}),
        lambda r: r["plan"].update(resource="financial"),
    ],
)
def test_untrusted_opa_obligations_fail_before_select(gateway, monkeypatch, mutation):
    client, _, db, _, _ = gateway
    transport = client.app.state.core.opa.client
    original = transport.post

    def post(url, **kwargs):
        response = original(url, **kwargs)
        body = response.json()
        mutation(body["result"])
        return httpx.Response(200, json=body, request=response.request)

    monkeypatch.setattr(transport, "post", post)
    response = read(gateway)
    assert response.status_code == 503
    assert response.json()["reason_code"] == "INVALID_OPA_RESPONSE"
    assert not db.calls


def test_single_opa_call_produces_complete_envelope(gateway, monkeypatch):
    client = gateway[0]
    transport = client.app.state.core.opa.client
    original = transport.post
    calls = []

    def post(url, **kwargs):
        calls.append(url)
        return original(url, **kwargs)

    monkeypatch.setattr(transport, "post", post)
    assert read(gateway).status_code == 200
    assert calls == ["/v1/data/gateway/evaluation?metrics=true"]


def test_replay_uses_history_after_registry_change_and_never_selects(gateway):
    client, headers, db, path, _ = gateway
    decision = read(gateway).json()
    registry = json.loads(path.read_text())
    registry["accounts"]["analyst"]["subject"]["department"] = "risk"
    path.write_text(json.dumps(registry))
    response = client.post(f"/api/v1/audit/{decision['request_id']}/replay", headers=headers)
    assert response.status_code == 200 and response.json()["status"] == "MATCH"
    assert len(db.calls) == 1
    assert read(gateway).status_code == 403


def test_missing_snapshot_is_unreplayable(gateway):
    client, headers, db, *_ = gateway
    response = client.post("/api/v1/audit/missing/replay", headers=headers)
    assert response.json()["status"] == "UNREPLAYABLE"
    assert not db.calls


def test_replay_missing_engine_is_unreplayable(gateway, monkeypatch):
    client, headers, *_ = gateway
    event = read(gateway).json()

    def failed(*args, **kwargs):
        raise httpx.ConnectError("Offline")

    monkeypatch.setattr(client.app.state.core.opa.client, "post", failed)
    result = client.post(f"/api/v1/audit/{event['request_id']}/replay", headers=headers)
    assert result.json()["status"] == "UNREPLAYABLE"


@pytest.mark.parametrize("phase", ["received", "intent", "response"])
def test_audit_failure_withholds_successful_data(gateway, monkeypatch, phase):
    client, _, db, *_ = gateway
    store = client.app.state.audit
    original = store.append

    def append(request_id, event_phase, *args, **kwargs):
        if event_phase == phase:
            raise sqlite3.OperationalError("Disk full")
        return original(request_id, event_phase, *args, **kwargs)

    monkeypatch.setattr(store, "append", append)
    response = read(gateway)
    assert response.status_code == 503 and "data" not in response.json()
    assert bool(db.calls) == (phase == "response")


def test_audit_encrypts_snapshot_and_rejects_cross_tenant_access(gateway):
    client, _, _, _, config = gateway
    event = read(gateway).json()
    store = client.app.state.audit
    assert store.snapshot(event["request_id"], "beta") is None
    assert store.snapshot(event["request_id"], "demo", "someone-else") is None
    assert (
        store.snapshot(event["request_id"], "demo", "analyst")["release"]["payload"][
            "engine_revision"
        ]
        == engine_revision()
    )
    with store.connect() as db:
        rows = db.execute("SELECT metadata,snapshot FROM audit").fetchall()
    serialized = json.dumps([tuple(row) for row in rows])
    for secret in (
        "correct-password",
        config["secret"],
        "access_token",
        '"attributes"',
        "Synthetic Customer",
    ):
        assert secret not in serialized


def test_audit_ciphertext_tamper_fails(gateway):
    client = gateway[0]
    event = read(gateway).json()
    store = client.app.state.audit
    with store.connect() as db:
        db.execute("UPDATE audit SET metadata='{}' WHERE phase='intent'")
    with pytest.raises(Exception):
        store.snapshot(event["request_id"], "demo")


def test_audit_backup_restore_preserves_replay(gateway, tmp_path):
    client, _, _, _, config = gateway
    event = read(gateway).json()
    store = client.app.state.audit
    path = tmp_path / "restore.sqlite"
    store.backup(path)
    restored = AuditStore(path, config["audit_key"])
    assert restored.snapshot(event["request_id"], "demo") == store.snapshot(
        event["request_id"], "demo"
    )


def test_early_auth_failure_is_durably_recorded(gateway):
    client, headers, db, *_ = gateway
    headers = {k: v for k, v in headers.items() if k != "authorization"}
    response = client.get("/api/v1/data/customers", headers=headers)
    with client.app.state.audit.connect() as store:
        row = store.execute(
            "SELECT metadata FROM audit WHERE request_id=? AND phase='response'",
            (response.json()["request_id"],),
        ).fetchone()
    assert json.loads(row[0])["http_status"] == 401
    assert not db.calls


def test_concurrent_reads_have_unique_audit_ids(gateway):
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: read(gateway), range(12)))
    assert all(r.status_code == 200 for r in responses)
    assert len({r.json()["request_id"] for r in responses}) == 12
    store = gateway[0].app.state.audit
    assert len(store.list("demo", "analyst")) == 12


def test_analyst_cannot_submit_impact_analysis(gateway):
    client, headers, *_ = gateway
    assert (
        client.post(
            "/api/v1/policies/impact", headers=headers, json={"revision": "a" * 64}
        ).status_code
        == 403
    )


def test_input_validation_does_not_echo_password(gateway):
    client, headers, *_ = gateway
    response = client.post(
        "/auth/login",
        headers=headers,
        json={"username": "analyst", "password": "sensitive", "extra": True},
    )
    assert response.status_code == 422
    assert "sensitive" not in response.text and "input" not in response.text


def test_impact_detects_access_changes_on_same_snapshot(gateway):
    from copy import deepcopy
    from app.gateway.releases import digest
    from app.gateway.evaluator import evaluate_snapshot, compare

    client, _, db, *_ = gateway
    event = read(gateway).json()
    snapshot = client.app.state.audit.snapshot(event["request_id"], "demo")
    candidate = deepcopy(snapshot["release"])
    candidate["payload"]["policies"].append(
        {
            "id": "P13",
            "description": "Restrict marketing reads",
            "version": "1.0.0",
            "reason_code": "TEMPORARY_RESTRICTION",
            "rationale": "Test explicit restriction",
            "effect": "Deny",
            "priority": 100,
            "baselines": ["context_abac"],
            "target": [],
            "conditions": [{"path": ["subject", "department"], "op": "eq", "value": "marketing"}],
        }
    )
    candidate["revision"] = digest(candidate["payload"])
    after = evaluate_snapshot(client.app.state.core.opa.client, snapshot["attributes"], candidate)
    assert after["decision"] == "DENY"
    assert "ALLOW->DENY" in compare(snapshot["evaluation"], after)
    assert "DENY->ALLOW" in compare(after, snapshot["evaluation"])
    assert len(db.calls) == 1
