"""Final-review regressions: session replay, persistent revocation and contract integrity."""

import json

import pytest

from app.gateway.api import load_registry
from app.gateway.security import decode_token
from app.gateway.sessions import Sessions

pytest_plugins = ["tests.integration.test_gateway"]


def test_logout_revokes_copied_token_before_protected_query(gateway):
    client, headers, db, _, _ = gateway
    assert client.post("/auth/logout", headers=headers).json()["revoked"]
    response = client.get("/api/v1/data/customers", headers=headers)
    assert response.status_code == 401 and not db.calls
    assert response.headers["x-request-id"] == response.json()["request_id"]


def test_token_cannot_move_to_another_enrolled_certificate(gateway):
    client, headers, db, path, _ = gateway
    registry = json.loads(path.read_text())
    registry["devices"]["B2"] = {"id": "other-device", "enabled": True}
    path.write_text(json.dumps(registry))
    response = client.get(
        "/api/v1/data/customers", headers={**headers, "x-gateway-device-serial": "B2"}
    )
    assert response.status_code == 401 and not db.calls


def test_session_revocation_survives_store_recreation(gateway):
    client, headers, _, _, config = gateway
    claims = decode_token(headers["authorization"][7:], config["secret"])
    store = client.app.state.sessions
    assert Sessions(store.path).active(claims)
    store.revoke(claims)
    assert not Sessions(store.path).active(claims)


def test_readiness_detects_database_failure_without_protected_select(gateway):
    client, headers, db, _, _ = gateway
    db.fail = True
    response = client.get("/health", headers=headers)
    assert response.status_code == 503 and not response.json()["database_ready"]
    assert not db.calls


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.update(unexpected=True),
        lambda r: r["accounts"]["analyst"].update(password_hash="plaintext"),
        lambda r: r["accounts"]["analyst"].update(auth_version=True),
        lambda r: r["devices"].update({"INVALID-HEX": {"id": "x", "enabled": True}}),
        lambda r: r["devices"]["A1"].update(enabled="true"),
    ],
)
def test_registry_schema_cannot_silently_ignore_ambiguous_security_fields(gateway, mutation):
    client, headers, db, path, _ = gateway
    registry = json.loads(path.read_text())
    mutation(registry)
    path.write_text(json.dumps(registry))
    with pytest.raises(ValueError):
        load_registry(path)
    assert client.get("/api/v1/data/customers", headers=headers).status_code == 503
    assert not db.calls


def test_unicode_proxy_secret_fails_closed_with_security_headers(gateway):
    client, headers, db, _, _ = gateway
    # Header bytes can contain non-ASCII; comparison must not raise TypeError.
    raw = [
        (key.encode(), value.encode())
        for key, value in headers.items()
        if key != "x-gateway-proxy-secret"
    ]
    raw.append((b"x-gateway-proxy-secret", b"\xff"))
    response = client.get("/api/v1/data/customers", headers=raw)
    assert response.status_code == 403 and response.headers["cache-control"] == "no-store"
    assert not db.calls
