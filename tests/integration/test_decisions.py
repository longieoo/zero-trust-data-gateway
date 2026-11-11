import json

import pytest
from fastapi.testclient import TestClient

from app.models import AccessRequest
from tests.policy_matrix.cases import BASE


@pytest.mark.parametrize("baseline", ["rbac", "static_abac", "context_abac"])
def test_only_context_baseline_changes_with_device(service, baseline):
    normal = service.evaluate(AccessRequest.model_validate({**BASE, "baseline": baseline}))
    changed = service.evaluate(
        AccessRequest.model_validate(
            {**BASE, "baseline": baseline, "context": {**BASE["context"], "device_trusted": False}}
        )
    )
    assert normal["decision"] == "ALLOW"
    assert changed["decision"] == ("DENY" if baseline == "context_abac" else "ALLOW")


@pytest.mark.parametrize(
    "risk,expected", [(0, "ALLOW"), (50, "ALLOW"), (69, "ALLOW"), (70, "DENY"), (100, "DENY")]
)
def test_risk_boundary(service, risk, expected):
    assert (
        service.evaluate(
            AccessRequest.model_validate(
                {**BASE, "context": {**BASE["context"], "risk_score": risk}}
            )
        )["decision"]
        == expected
    )


def test_real_rego_indeterminate_and_not_applicable(service):
    policies = json.loads(service.policy_path.read_text())
    outcomes = service.opa.evaluate(
        {"subject": {"role": "intern"}, "resource": {"type": "report"}, "action": "read"},
        "context_abac",
        policies,
        "none",
    )
    assert {row["outcome"] for row in outcomes} >= {"Permit", "NotApplicable", "Indeterminate"}


def test_trace_and_protected_resource(service, monkeypatch):
    import app.api as api

    monkeypatch.setattr(api, "service", service)
    client = TestClient(api.app)
    assert client.get("/health").json()["opa_ready"]
    for route in ("subjects", "resources", "scenarios"):
        assert client.get("/" + route).status_code == 200
    for trusted in (True, False):
        result = client.post(
            "/protected", json={**BASE, "context": {**BASE["context"], "device_trusted": trusted}}
        ).json()
        assert (result["resource"] is not None) == trusted
        response = result["authorization"]
        trace = response["trace"]
        assert response["decision"] == trace["decision"]
        assert response["explanation"] == trace["explanation"]
        winner = next(
            p for p in trace["policy_outcomes"] if p["id"] == response["winning_policies"][0]
        )
        assert winner["description"] == response["explanation"]
    no_trace = client.post("/evaluate", json={**BASE, "trace": False}).json()
    assert no_trace["decision"] == "ALLOW" and no_trace["trace"] is None


def test_explicit_production_delete_and_all_permit_policies(service):
    for subject, action, resource, reason, decision in [
        ("engineer", "write", "production_db", "WRITE_PERMISSION", "ALLOW"),
        ("admin", "delete", "risk_dataset", "ADMIN_DELETE", "ALLOW"),
        ("admin", "delete", "production_db", "PRODUCTION_DELETE_PROHIBITED", "DENY"),
    ]:
        result = service.evaluate(
            AccessRequest.model_validate(
                {**BASE, "subject_id": subject, "action": action, "resource_id": resource}
            )
        )
        assert (result["decision"], result["reason_code"]) == (decision, reason)
