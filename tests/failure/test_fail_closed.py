import json

import httpx
import pytest

from app.models import AccessRequest
from tests.policy_matrix.cases import BASE


@pytest.mark.parametrize(
    "failure",
    [
        "opa_unavailable",
        "opa_timeout",
        "provider_unavailable",
        "invalid_opa_response",
        "undefined_result",
        "invalid_policy",
        "missing_attribute",
        "stale_attribute",
    ],
)
@pytest.mark.parametrize("strategy", ["deny-overrides", "permit-overrides", "priority-based"])
def test_failure_never_permits(service, failure, strategy):
    result = service.evaluate(
        AccessRequest.model_validate({**BASE, "failure_mode": failure, "strategy": strategy})
    )
    assert result["decision"] == "DENY"
    assert result["decision_status"] == "DENIED_DUE_TO_TECHNICAL_FAILURE"


@pytest.mark.parametrize(
    "problem,reason",
    [
        (httpx.ConnectError("offline"), "OPA_UNAVAILABLE"),
        (httpx.ReadTimeout("deadline"), "OPA_TIMEOUT"),
    ],
)
def test_actual_transport_exception_path(service, monkeypatch, problem, reason):
    def fail(*args, **kwargs):
        raise problem

    monkeypatch.setattr(service.opa.client, "post", fail)
    result = service.evaluate(AccessRequest.model_validate(BASE))
    assert result["decision"] == "DENY" and result["reason_code"] == reason


def test_server_context_and_disabled_simulation(service):
    service.simulation = False
    assert (
        service.evaluate(AccessRequest.model_validate(BASE))["reason_code"]
        == "CLIENT_CONTEXT_FORBIDDEN"
    )
    request = {key: value for key, value in BASE.items() if key != "context"}
    assert service.evaluate(AccessRequest.model_validate(request))["decision"] == "ALLOW"
    (service.provider.root / "contexts.json").write_text("{}")
    assert (
        service.evaluate(AccessRequest.model_validate(request))["reason_code"]
        == "MISSING_ATTRIBUTE"
    )


def test_provider_file_missing_and_invalid_domain(service):
    path = service.provider.root / "users.json"
    rows = json.loads(path.read_text())
    rows[1]["attributes"]["clearance"] = "superuser"
    path.write_text(json.dumps(rows))
    assert (
        service.evaluate(AccessRequest.model_validate(BASE))["reason_code"] == "INVALID_ATTRIBUTE"
    )
    path.unlink()
    assert (
        service.evaluate(AccessRequest.model_validate(BASE))["reason_code"]
        == "PROVIDER_UNAVAILABLE"
    )


def test_dev_failure_disabled(service):
    service.dev_failures = False
    assert (
        service.evaluate(AccessRequest.model_validate({**BASE, "failure_mode": "opa_timeout"}))[
            "reason_code"
        ]
        == "FAILURE_INJECTION_DISABLED"
    )


def test_stale_trace_exposes_actual_freshness_failure(service):
    result = service.evaluate(
        AccessRequest.model_validate({**BASE, "failure_mode": "stale_attribute"})
    )
    evidence = result["trace"]["failure"]["evidence"]
    assert evidence["fresh"] is False
    assert evidence["age_seconds"] >= evidence["ttl_seconds"]
    assert evidence["timestamp"].startswith("2000-01-01")
