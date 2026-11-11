import json

import httpx
import pytest

from app.models import AccessRequest
from tests.policy_matrix.cases import BASE


@pytest.mark.parametrize("body", ["not json", "null", '{"result": null}', '{"result": [42]}', "{}"])
def test_malformed_http_payloads_fail_closed(service, monkeypatch, body):
    def malformed(*args, **kwargs):
        return httpx.Response(
            200, content=body, request=httpx.Request("POST", "http://opa.test/evaluate")
        )

    monkeypatch.setattr(service.opa.client, "post", malformed)
    result = service.evaluate(AccessRequest.model_validate(BASE))
    assert result["decision"] == "DENY"
    assert result["decision_status"] == "DENIED_DUE_TO_TECHNICAL_FAILURE"


def test_malformed_condition_record_cannot_escape_response_validation(service, monkeypatch):
    request = AccessRequest.model_validate(BASE)
    valid = service.evaluate(request)
    outcomes = valid["trace"]["policy_outcomes"]
    outcomes[0]["conditions"][0] = 42

    def malformed(*args, **kwargs):
        return httpx.Response(
            200,
            json={"result": outcomes},
            request=httpx.Request("POST", "http://opa.test/evaluate"),
        )

    monkeypatch.setattr(service.opa.client, "post", malformed)
    result = service.evaluate(request)
    assert result["decision"] == "DENY"
    assert result["reason_code"] == "INVALID_OPA_RESPONSE"


def test_malformed_provider_structure_is_technical_denial(service):
    (service.provider.root / "users.json").write_text(json.dumps([{"attributes": None}]))
    result = service.evaluate(AccessRequest.model_validate(BASE))
    assert result["decision"] == "DENY"
    assert result["decision_status"] == "DENIED_DUE_TO_TECHNICAL_FAILURE"
