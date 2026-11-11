import pytest

from app.decision import combine
from benchmark.generate_policies import generate
from benchmark.oracle import decide


@pytest.mark.parametrize("count", [10, 100, 500, 1000, 5000])
@pytest.mark.parametrize("risk,expected", [(20, "ALLOW"), (90, "DENY")])
def test_real_opa_benchmark_anchor_controls(service, count, risk, expected):
    """A deliberately unmatched control resource isolates known anchor behavior."""
    attributes = {
        "resource": {"id": "oracle_control_report"},
        "action": "read",
        "context": {"risk_score": risk, "location": "office"},
    }
    policies = generate(count)
    assert decide(attributes, policies) == expected
    outcomes = service.opa.evaluate(attributes, "context_abac", policies, "none")
    assert combine(outcomes, "deny-overrides")["decision"] == expected
