"""Real OPA decisions plus observable enforcement boundaries; database E2E is separate."""

import json
from datetime import datetime, timedelta, timezone

import jwt
import httpx
import pytest
from fastapi.testclient import TestClient

from app.gateway.api import create_app
from app.gateway.database import ViewPlan
from app.gateway.security import hash_password, issue_token, decode_token
from app.services import ROOT
from app.gateway.releases import engine_revision


class ObservedDatabase:
    def __init__(self):
        self.calls = []
        self.fail = False

    def query(self, plan):
        self.calls.append(plan)
        if self.fail:
            raise RuntimeError("Database offline")
        return [{"id": 1, "department": "marketing", "email": "REDACTED"}]

    def close(self):
        pass

    def ready(self):
        return not self.fail


@pytest.fixture
def gateway(tmp_path, monkeypatch, real_opa):
    monkeypatch.setenv("OPA_URL", "http://127.0.0.1:18181")
    monkeypatch.delenv("POLICY_FILE", raising=False)
    path = tmp_path / "registry.json"
    registry = {
        "accounts": {
            "analyst": {
                "subject": {
                    "id": "analyst",
                    "tenant_id": "demo",
                    "role": "marketing_analyst",
                    "department": "marketing",
                    "clearance": "confidential",
                },
                "password_hash": hash_password("correct-password"),
                "enabled": True,
                "auth_version": 1,
            }
        },
        "devices": {"A1": {"id": "test-device", "enabled": True}},
    }
    path.write_text(json.dumps(registry))
    config = {
        "secret": "a" * 64,
        "allow_unsigned_policies": True,
        "audit_file": str(tmp_path / "audit.sqlite"),
        "audit_key": "c" * 64,
        "proxy_secret": "b" * 64,
        "registry": str(path),
        "database_url": "unused",
        "office_networks": "127.0.0.0/8",
        "timezone": "Asia/Bangkok",
        "policy_file": str(ROOT / "policies/policies.json"),
    }
    now = datetime(2026, 10, 7, 2, tzinfo=timezone.utc)  # 09:00 business time
    db = ObservedDatabase()
    app = create_app(config, db, clock=lambda: now)
    uploaded = app.state.core.opa.client.put(
        "/v1/policies/gateway",
        content=(ROOT / "policies/gateway.rego").read_bytes(),
        headers={"Content-Type": "text/plain"},
    )
    uploaded.raise_for_status()
    app.state.core.opa.client.put(
        "/v1/data/deployment", json={"engine_revision": engine_revision()}
    ).raise_for_status()
    headers = {
        "x-gateway-proxy-secret": config["proxy_secret"],
        "x-gateway-client-ip": "127.0.0.1",
        "x-gateway-device-verified": "SUCCESS",
        "x-gateway-device-serial": "A1",
        "authorization": "Bearer " + issue_token("analyst", config["secret"], 1, "A1"),
    }
    app.state.sessions.add(decode_token(headers["authorization"][7:], config["secret"]))
    with TestClient(app) as client:
        yield client, headers, db, path, config


def test_authenticated_allow_has_mask_and_department_obligations(gateway):
    client, headers, db, _, _ = gateway
    result = client.get("/api/v1/data/customers", headers=headers)
    assert result.status_code == 200
    assert result.json()["obligations"]["mask"] == ["email", "salary", "national_id"]
    assert db.calls[0].row_scope.value == "marketing"
    assert result.json()["context"]["source"] == "verified TLS proxy + server clock"


@pytest.mark.parametrize(
    "change",
    [
        {"x-gateway-device-verified": "NONE"},
        {"x-gateway-device-serial": "NOT-ENROLLED"},
        {"x-gateway-client-ip": "203.0.113.1"},
    ],
)
def test_untrusted_context_never_queries_protected_database(gateway, change):
    client, headers, db, _, _ = gateway
    result = client.get("/api/v1/data/customers", headers={**headers, **change})
    assert result.status_code in (401, 403) and result.json()["decision"] == "DENY"
    assert not db.calls


def test_device_revocation_is_seen_on_next_request(gateway):
    client, headers, db, path, _ = gateway
    registry = json.loads(path.read_text())
    registry["devices"]["A1"]["enabled"] = False
    path.write_text(json.dumps(registry))
    assert client.get("/api/v1/data/customers", headers=headers).status_code == 403
    assert not db.calls


@pytest.mark.parametrize(
    "kind", ["missing", "expired", "forged", "wrong_audience", "missing_claim"]
)
def test_identity_failures_never_query_database(gateway, kind):
    client, headers, db, _, config = gateway
    now = datetime.now(timezone.utc)
    claims = {
        "sub": "analyst",
        "iss": "abac-gateway",
        "aud": "abac-data",
        "exp": now + timedelta(minutes=1),
        "nbf": now,
        "iat": now,
        "jti": "test",
        "auth_version": 1,
    }
    if kind == "missing":
        headers = {k: v for k, v in headers.items() if k != "authorization"}
    else:
        if kind == "expired":
            claims["exp"] = now - timedelta(minutes=1)
        if kind == "wrong_audience":
            claims["aud"] = "other-app"
        if kind == "missing_claim":
            del claims["exp"]
        headers = {
            **headers,
            "authorization": "Bearer "
            + jwt.encode(
                claims, "z" * 64 if kind == "forged" else config["secret"], algorithm="HS256"
            ),
        }
    assert client.get("/api/v1/data/customers", headers=headers).status_code == 401
    assert not db.calls


@pytest.mark.parametrize("field,value", [("enabled", False), ("auth_version", 2)])
def test_account_disable_or_version_revokes_existing_token(gateway, field, value):
    client, headers, db, path, _ = gateway
    registry = json.loads(path.read_text())
    registry["accounts"]["analyst"][field] = value
    path.write_text(json.dumps(registry))
    assert client.get("/api/v1/data/customers", headers=headers).status_code == 401
    assert not db.calls


def test_proxy_spoofing_is_denied(gateway):
    client, headers, db, _, _ = gateway
    headers["x-gateway-proxy-secret"] = "forged"
    assert client.get("/api/v1/data/customers", headers=headers).status_code == 403
    assert not db.calls


@pytest.mark.parametrize(
    "query", ["subject_id=admin", "device_trusted=true", "strategy=permit-overrides", "sql=SELECT"]
)
def test_gateway_rejects_client_overrides(gateway, query):
    client, headers, db, _, _ = gateway
    assert client.get("/api/v1/data/customers?" + query, headers=headers).status_code == 422
    assert not db.calls


def test_login_and_wrong_password(gateway):
    client, headers, _, _, _ = gateway
    assert (
        client.post(
            "/auth/login", headers=headers, json={"username": "analyst", "password": "wrong"}
        ).status_code
        == 401
    )
    result = client.post(
        "/auth/login", headers=headers, json={"username": "analyst", "password": "correct-password"}
    )
    assert result.status_code == 200 and result.json()["expires_in"] == 600


def test_database_failure_withholds_data(gateway):
    client, headers, db, _, _ = gateway
    db.fail = True
    result = client.get("/api/v1/data/customers", headers=headers)
    assert result.status_code == 503 and "data" not in result.json()


def test_malformed_registry_fails_closed(gateway):
    client, headers, db, path, _ = gateway
    path.write_text('{"accounts":{},"accounts":{}}')
    assert client.get("/api/v1/data/customers", headers=headers).status_code == 503
    assert not db.calls


def test_missing_obligations_fail_closed_before_database(gateway, monkeypatch):
    client, headers, db, _, _ = gateway
    transport = client.app.state.core.opa.client
    original = transport.post

    def post(url, **kwargs):
        if url.startswith("/v1/data/gateway/evaluation"):
            return httpx.Response(200, json={}, request=httpx.Request("POST", "http://opa" + url))
        return original(url, **kwargs)

    monkeypatch.setattr(transport, "post", post)
    assert client.get("/api/v1/data/customers", headers=headers).status_code == 503
    assert not db.calls


def test_opa_transport_failure_never_queries_database(gateway, monkeypatch):
    client, headers, db, _, _ = gateway

    def failed(*args, **kwargs):
        raise httpx.ConnectError("Unavailable")

    monkeypatch.setattr(client.app.state.core.opa.client, "post", failed)
    assert client.get("/api/v1/data/customers", headers=headers).status_code == 503
    assert not db.calls


def test_login_rate_limit_is_enforced(gateway):
    client, headers, _, _, _ = gateway
    codes = [
        client.post(
            "/auth/login", headers=headers, json={"username": "analyst", "password": "wrong"}
        ).status_code
        for _ in range(11)
    ]
    assert codes == [401] * 10 + [429]


@pytest.mark.parametrize(
    "mutation",
    [
        {"mask": ["unknown"]},
        {"columns": ["id;DROP TABLE customer_data"]},
        {"limit": 101},
        {"row_scope": {"kind": "department"}},
        {"version": 2},
        {"columns": ["id", "id"]},
        {"extra": "unsupported"},
    ],
)
def test_obligation_contract_rejects_unknown_or_unsafe_operations(mutation):
    plan = {
        "version": 1,
        "tenant_id": "demo",
        "policy_revision": "a" * 64,
        "resource": "customers",
        "columns": ["id", "email"],
        "mask": ["email"],
        "row_scope": {"kind": "all"},
        "limit": 100,
    }
    with pytest.raises(ValueError):
        ViewPlan.model_validate({**plan, **mutation})
