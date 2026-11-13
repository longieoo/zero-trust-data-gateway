"""Security regression tests for signed obligations and durable audit readiness."""

import sqlite3
from contextlib import contextmanager
from copy import deepcopy

import httpx
import pytest

from app.attribute_provider import DecisionError
from app.gateway.audit import AuditStore
from app.gateway.evaluator import evaluate_snapshot
from app.gateway.releases import canonical, digest, engine_revision, verify_release


def envelope(role="admin", mask_admin=True, limit=7):
    policy = {
        "id": "ALLOW",
        "description": "Synthetic permit",
        "version": "1",
        "reason_code": "PERMIT",
        "rationale": "Test permit",
        "priority": 1,
        "effect": "Permit",
        "baselines": ["context_abac"],
        "target": [],
        "conditions": [],
    }
    payload = {
        "schema": 1,
        "policies": [policy],
        "view": {"mask_admin": mask_admin, "limit": limit},
        "engine_revision": engine_revision(),
        "description": "Synthetic signed-profile fixture",
    }
    release = {"revision": digest(payload), "payload": payload, "signatures": {}}
    attributes = {
        "subject": {"id": "alice", "role": role, "tenant_id": "demo", "department": "marketing"},
        "resource": {"id": "customers"},
    }
    result = {
        "revision": release["revision"],
        "engine_revision": payload["engine_revision"],
        "contract": "gateway-5.0.0",
        "outcomes": [
            {
                "id": "ALLOW",
                "description": "Synthetic permit",
                "priority": 1,
                "version": "1",
                "reason_code": "PERMIT",
                "target_match": True,
                "conditions": [],
                "outcome": "Permit",
            }
        ],
        "plan": {
            "version": 1,
            "tenant_id": "demo",
            "policy_revision": release["revision"],
            "resource": "customers",
            "columns": ["id", "department", "name", "email", "salary", "national_id"],
            "mask": ["email", "salary", "national_id"] if role != "admin" or mask_admin else [],
            "row_scope": {"kind": "all"}
            if role == "admin"
            else {"kind": "department", "value": "marketing"},
            "limit": limit,
        },
    }
    return attributes, release, result


def evaluate_fixture(attributes, release, result):
    with httpx.Client(
        base_url="http://opa",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"result": result})),
    ) as client:
        return evaluate_snapshot(client, attributes, release)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r["plan"].update(mask=[]),
        lambda r: r["plan"].update(limit=100),
        lambda r: r["plan"].update(columns=["id", "email", "salary", "national_id"]),
        lambda r: r["plan"].update(row_scope={"kind": "department", "value": "marketing"}),
    ],
)
def test_correct_revision_cannot_hide_obligation_drift(mutation):
    attributes, release, result = envelope()
    mutation(result)
    with pytest.raises(DecisionError) as raised:
        evaluate_fixture(attributes, release, result)
    assert raised.value.code == "INVALID_OPA_RESPONSE"


@pytest.mark.parametrize(
    "role,mask_admin", [("admin", True), ("admin", False), ("marketing_analyst", False)]
)
def test_exact_obligations_match_signed_profile(role, mask_admin):
    attributes, release, result = envelope(role, mask_admin)
    evaluated = evaluate_fixture(attributes, release, result)
    assert evaluated["decision"] == "ALLOW"
    assert evaluated["obligations"]["limit"] == 7


def test_additional_unapproved_mask_is_also_profile_drift():
    attributes, release, result = envelope(mask_admin=False)
    result["plan"]["mask"] = ["email"]
    with pytest.raises(DecisionError):
        evaluate_fixture(attributes, release, result)


@pytest.mark.parametrize("result", [None, [], "ALLOW", {"revision": "fake"}])
def test_malformed_pdp_envelope_is_a_classified_failure(result):
    attributes, release, _ = envelope()
    with pytest.raises(DecisionError) as raised:
        evaluate_fixture(attributes, release, result)
    assert raised.value.code == "INVALID_OPA_RESPONSE"


def test_audit_health_probes_write_without_recording_fake_events(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite", "ab" * 32)
    store.append("request-1", "received", {"method": "GET"})
    assert store.ready()
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM audit").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM audit_health").fetchone()[0] == 0


def test_audit_health_rejects_read_only_database(tmp_path, monkeypatch):
    store = AuditStore(tmp_path / "audit.sqlite", "ab" * 32)

    @contextmanager
    def read_only():
        db = sqlite3.connect(store.path.as_uri() + "?mode=ro", uri=True)
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(store, "connect", read_only)
    assert store.ready() is False


@pytest.mark.parametrize("limit", [0, -1, 101, True, "20"])
def test_audit_queries_are_bounded_even_outside_http(tmp_path, limit):
    store = AuditStore(tmp_path / "audit.sqlite", "ab" * 32)
    with pytest.raises(ValueError):
        store.list("demo", limit=limit)


def test_audit_rejects_oversized_metadata_before_persistence(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite", "ab" * 32)
    with pytest.raises(ValueError):
        store.append("request-1", "response", {"oversized": "x" * 64001})
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM audit").fetchone()[0] == 0


@pytest.mark.parametrize("quorum", [0, -1, True, 3])
def test_signature_verifier_cannot_be_configured_to_skip_approval(quorum):
    with pytest.raises(ValueError):
        verify_release({}, {}, required=quorum)


def test_canonical_release_encoding_rejects_nonfinite_numbers():
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            canonical({"value": value})


def test_unknown_signer_is_a_normal_validation_error():
    _, release, _ = envelope()
    malformed = deepcopy(release)
    malformed["signatures"] = {"unknown": "YWJj"}
    with pytest.raises(ValueError, match="untrusted signature"):
        verify_release(malformed, {})
