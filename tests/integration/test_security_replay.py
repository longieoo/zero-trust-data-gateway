"""Historical corruption is unreplayable, never a fabricated match or data read."""

import base64

import pytest

pytest_plugins = ["tests.integration.test_gateway"]


@pytest.mark.parametrize(
    "snapshot",
    [
        None,
        [],
        True,
        "legacy-invalid",
        {"schema": 1, "release": None},
        {"schema": 1, "release": []},
    ],
)
def test_authenticated_malformed_history_is_explicitly_unreplayable(gateway, snapshot):
    client, headers, db, *_ = gateway
    client.app.state.audit.append(
        "legacy-malformed",
        "intent",
        {"route": "/api/v1/data/{resource}"},
        snapshot,
        "demo",
        "analyst",
    )
    response = client.post("/api/v1/audit/legacy-malformed/replay", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "UNREPLAYABLE"
    assert response.json()["db_queried"] is False
    assert not db.calls


@pytest.mark.parametrize("sealed", ["not-base64!", "AA==", base64.b64encode(b"x" * 40).decode()])
def test_corrupt_encrypted_history_is_explicitly_unreplayable(gateway, sealed):
    client, headers, db, *_ = gateway
    store = client.app.state.audit
    store.append("corrupt-history", "intent", {}, {"schema": 1}, "demo", "analyst")
    with store.connect() as connection:
        connection.execute(
            "UPDATE audit SET snapshot=? WHERE request_id=?", (sealed, "corrupt-history")
        )
    response = client.post("/api/v1/audit/corrupt-history/replay", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "UNREPLAYABLE"
    assert response.json()["db_queried"] is False
    assert not db.calls
