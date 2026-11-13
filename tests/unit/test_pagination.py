from datetime import datetime, timedelta, timezone

import pytest

from app.gateway.pagination import issue_cursor, read_cursor


@pytest.mark.parametrize(
    "mutation",
    ["tenant", "role", "session", "resource", "revision", "size", "expired", "signature"],
)
def test_cursor_cannot_escape_its_original_context(mutation):
    now = datetime.now(timezone.utc)
    subject = {"id": "alice", "tenant_id": "demo", "role": "marketing_analyst"}
    args = ["s" * 64, subject, "session-1", "customers", "a" * 64, 20]
    token = issue_cursor(*args, 17, now)
    assert read_cursor(token, *args, now) == 17
    if mutation in {"tenant", "role"}:
        subject = {**subject, "tenant_id" if mutation == "tenant" else "role": "other"}
        args[1] = subject
    elif mutation == "session":
        args[2] = "session-2"
    elif mutation == "resource":
        args[3] = "financial"
    elif mutation == "revision":
        args[4] = "b" * 64
    elif mutation == "size":
        args[5] = 21
    elif mutation == "expired":
        now += timedelta(minutes=11)
    else:
        token = "X" + token[1:]
    with pytest.raises(ValueError):
        read_cursor(token, *args, now)
