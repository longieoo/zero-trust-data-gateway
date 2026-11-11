import json
import random

import pytest

from app.models import AccessRequest
from tests.policy_matrix.cases import BASE


@pytest.mark.parametrize("strategy", ["deny-overrides", "permit-overrides", "priority-based"])
def test_policy_order_invariance(service, strategy):
    request = AccessRequest.model_validate(
        {
            **BASE,
            "strategy": strategy,
            "context": {**BASE["context"], "device_trusted": False, "risk_score": 90},
        }
    )
    expected = service.evaluate(request)
    policies = json.loads(service.policy_path.read_text())
    random.Random(42).shuffle(policies)
    service.policy_path.write_text(json.dumps(policies))
    actual = service.evaluate(request)
    for key in (
        "decision",
        "reason_code",
        "explanation",
        "winning_policies",
        "effective_policies",
        "conflict",
    ):
        assert actual[key] == expected[key]


def test_priority_can_choose_higher_permit(service):
    policies = json.loads(service.policy_path.read_text())
    policies[0]["priority"] = 999
    service.policy_path.write_text(json.dumps(policies))
    result = service.evaluate(
        AccessRequest.model_validate(
            {
                **BASE,
                "strategy": "priority-based",
                "context": {**BASE["context"], "device_trusted": False},
            }
        )
    )
    assert result["decision"] == "ALLOW"
    assert result["conflict"]
    assert result["winning_policies"] == ["P01"]


@pytest.mark.parametrize(
    "time,expected",
    [
        ("2026-01-15T08:00:00Z", "ALLOW"),
        ("2026-01-15T17:59:59Z", "ALLOW"),
        ("2026-01-15T15:00:00+07:00", "ALLOW"),
        ("2026-01-15T14:59:59+07:00", "DENY"),
    ],
)
def test_time_boundaries_and_timezone(service, time, expected):
    result = service.evaluate(
        AccessRequest.model_validate({**BASE, "context": {**BASE["context"], "time": time}})
    )
    assert result["decision"] == expected


def test_trace_off_preserves_decision_semantics(service):
    for trusted in (True, False):
        request = {**BASE, "context": {**BASE["context"], "device_trusted": trusted}}
        on = service.evaluate(AccessRequest.model_validate(request))
        off = service.evaluate(AccessRequest.model_validate({**request, "trace": False}))
        for key in (
            "decision",
            "decision_status",
            "reason_code",
            "explanation",
            "effective_policies",
            "winning_policies",
            "conflict",
        ):
            assert on[key] == off[key]
        assert off["trace"] is None
