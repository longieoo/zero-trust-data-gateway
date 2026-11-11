from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.attribute_provider import AttributeProvider, DecisionError
from app.decision import combine
from app.models import AccessRequest, Context
from app.opa_client import validate_outcomes
from tests.policy_matrix.cases import BASE


@pytest.mark.parametrize(
    "field,value",
    [
        ("risk_score", -1),
        ("risk_score", 101),
        ("risk_score", True),
        ("device_trusted", "false"),
        ("location", "moon"),
        ("time", "2026-01-01T10:00:00"),
    ],
)
def test_context_domains(field, value):
    with pytest.raises(ValidationError):
        Context.model_validate({**BASE["context"], field: value})


def test_spoofed_role_rejected():
    with pytest.raises(ValidationError):
        AccessRequest.model_validate({**BASE, "role": "admin"})


@pytest.mark.parametrize("age,valid", [(299.999, True), (300, False), (301, False), (-1, False)])
def test_freshness_boundary(age, valid):
    now = datetime.now(timezone.utc)
    entry = {
        "attributes": BASE["context"],
        "timestamp": (now - timedelta(seconds=age)).isoformat(),
        "ttl_seconds": 300,
    }
    if valid:
        assert AttributeProvider.validate(entry, Context, now, "fixture")[1]["risk_score"]["fresh"]
    else:
        with pytest.raises(DecisionError):
            AttributeProvider.validate(entry, Context, now, "fixture")


@pytest.mark.parametrize("strategy", ["deny-overrides", "permit-overrides", "priority-based"])
def test_indeterminate_dominates_every_strategy(strategy):
    rows = [
        {
            "id": "a",
            "outcome": "Permit",
            "priority": 999,
            "reason_code": "OK",
            "description": "Granted",
        },
        {
            "id": "b",
            "outcome": "Indeterminate",
            "priority": 1,
            "reason_code": "ERROR",
            "description": "Failed",
        },
    ]
    result = combine(rows, strategy)
    assert result["decision"] == "DENY"
    assert result["decision_status"] == "DENIED_DUE_TO_TECHNICAL_FAILURE"
    assert result["combining_rule"] == "fail-closed-indeterminate"


def test_response_semantics_reject_allow_and_duplicates():
    policy = {
        "id": "P",
        "baselines": ["rbac"],
        "priority": 1,
        "version": "1",
        "reason_code": "R",
        "description": "text",
        "conditions": [],
        "effect": "Deny",
    }
    row = {**policy, "outcome": "Permit", "target_match": True}
    with pytest.raises(ValueError):
        validate_outcomes([row], [policy], "rbac")
    row["outcome"] = "Deny"
    with pytest.raises(ValueError):
        validate_outcomes([row, deepcopy(row)], [policy], "rbac")
