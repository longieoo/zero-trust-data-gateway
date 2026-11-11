import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.models import AccessRequest
from app.services import ROOT
from tests.policy_matrix.cases import CASES

RESULTS = []


@pytest.fixture(scope="module", autouse=True)
def save_results():
    yield
    target = ROOT / "tests/policy_matrix/results.json"
    target.write_text(json.dumps(RESULTS, indent=2), encoding="utf-8")


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["test_id"])
def test_matrix(case, service, monkeypatch):
    fixture = case["fixture"]
    policies = json.loads(service.policy_path.read_text())
    now = datetime.now(timezone.utc)
    if fixture == "empty":
        policies = []
    elif fixture == "equal":
        for p in policies:
            p["priority"] = 10
    elif fixture == "reverse":
        policies.reverse()
    elif fixture == "invalid":
        policies[0]["conditions"][0]["op"] = "run_python"
    elif fixture == "ttl_boundary":
        path = service.provider.root / "users.json"
        rows = json.loads(path.read_text())
        for row in rows:
            row["timestamp"] = (now - timedelta(seconds=row["ttl_seconds"])).isoformat()
        path.write_text(json.dumps(rows))
    service.policy_path.write_text(json.dumps(policies))
    if case["test_id"] == "TC25":
        import app.api as api

        monkeypatch.setattr(api, "service", service)
        result = TestClient(api.app).post("/evaluate", json=case["input"]).json()
    else:
        result = service.evaluate(AccessRequest.model_validate(case["input"]), now=now)
    passed = (
        result["decision"] == case["expected_result"]
        and result["reason_code"] == case["expected_reason"]
    )
    trace = result["trace"]
    RESULTS.append(
        {
            **case,
            "model": case["input"]["baseline"],
            "strategy": case["input"]["strategy"],
            "actual_result": result["decision"],
            "reason_code": result["reason_code"],
            "explanation": result["explanation"],
            "decision_status": result["decision_status"],
            "candidate_policies": trace.get("candidate_policies", []),
            "applicable_policies": trace.get("applicable_policies", []),
            "effective_policies": result.get("effective_policies", []),
            "pass": passed,
        }
    )
    assert passed, result
    assert trace["decision"] == result["decision"]
    assert trace["explanation"] == result["explanation"]
