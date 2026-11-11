from benchmark.generate_policies import generate
from benchmark.oracle import decide


def test_oracle_has_known_independent_anchor_decisions():
    attributes = {"action": "read", "context": {"risk_score": 20}}
    assert decide(attributes, generate(2)) == "ALLOW"
    attributes["context"]["risk_score"] = 70
    assert decide(attributes, generate(2)) == "DENY"


def test_generator_is_deterministic_and_varied():
    policies = generate(5000)
    assert policies == generate(5000)
    assert len({p["id"] for p in policies}) == 5000
    assert {p["effect"] for p in policies} == {"Permit", "Deny"}
    assert len({p["priority"] for p in policies}) > 100
