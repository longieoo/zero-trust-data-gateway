import json

import pytest

pytest_plugins = ["tests.integration.test_gateway"]


def test_keyset_page_never_accepts_tampered_cursor_or_identity_change(gateway):
    client, headers, db, path, _ = gateway
    seen = []

    def page(plan, after_id):
        seen.append((plan, after_id))
        return [{"id": after_id + 1, "email": "REDACTED"}], after_id == 0

    db.page = page
    first = client.get("/api/v1/data/customers?page_size=1", headers=headers)
    assert first.status_code == 200
    cursor = first.json()["pagination"]["next_cursor"]
    second = client.get(
        "/api/v1/data/customers", params={"page_size": 1, "cursor": cursor}, headers=headers
    )
    assert second.status_code == 200 and second.json()["data"][0]["id"] == 2
    assert seen[0][0].limit == 1 and seen[1][1] == 1
    assert not second.json()["pagination"]["has_more"]
    broken = client.get(
        "/api/v1/data/customers", params={"page_size": 1, "cursor": "X" + cursor}, headers=headers
    )
    assert broken.status_code == 422 and broken.json()["db_queried"] is False
    registry = json.loads(path.read_text())
    registry["accounts"]["analyst"]["subject"]["department"] = "risk"
    path.write_text(json.dumps(registry))
    changed = client.get(
        "/api/v1/data/customers", params={"page_size": 1, "cursor": cursor}, headers=headers
    )
    assert changed.status_code == 422 and len(seen) == 2


@pytest.mark.parametrize(
    "query",
    ["page_size=0", "page_size=101", "page_size=wrong", "cursor=abc", "page_size=1&page_size=2"],
)
def test_invalid_pagination_never_reaches_database(gateway, query):
    client, headers, db, *_ = gateway
    response = client.get("/api/v1/data/customers?" + query, headers=headers)
    assert response.status_code == 422 and not db.calls


def test_session_store_outage_is_visible_in_readiness(gateway, monkeypatch):
    client, headers, *_ = gateway

    def unavailable():
        raise RuntimeError("Session storage unavailable")

    monkeypatch.setattr(client.app.state.sessions, "ready", unavailable)
    response = client.get("/health", headers=headers)
    assert response.status_code == 503 and response.json()["session_ready"] is False
