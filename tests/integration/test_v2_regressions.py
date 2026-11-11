import json
import os
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone

import httpx
import pytest

from app.models import AccessRequest
from app.opa_client import expand_compact, validate_outcomes
from tests.policy_matrix.cases import BASE
from benchmark.generate_policies import generate
from app.jsonio import strict_json_loads


@pytest.mark.parametrize(
    "field,value",
    [
        ("target", None),
        ("conditions", [42]),
        ("baselines", "context_abac"),
        ("priority", True),
        ("id", []),
    ],
)
def test_invalid_catalogue_never_reuses_previous_permit(service, field, value):
    assert service.evaluate(AccessRequest.model_validate(BASE))["decision"] == "ALLOW"
    policies = json.loads(service.policy_path.read_text())
    policies[0][field] = value
    service.policy_path.write_text(json.dumps(policies))
    result = service.evaluate(AccessRequest.model_validate(BASE))
    assert result["reason_code"] == "INVALID_POLICY"
    assert result["decision"] == "DENY"


@pytest.mark.parametrize(
    "condition",
    [
        {"path": ["context", "risk_score"], "op": "gte", "value": "70"},
        {"path": ["action"], "op": "in", "value": "read"},
        {"path": ["action"], "op": "eq", "value": "read", "other": ["action"]},
        {"path": ["subject", "role"], "op": "lt", "value": 7},
        {"path": ["context", "risk_score"], "op": "gte", "other": ["subject", "role"]},
        {"path": ["unknown"], "op": "eq", "value": "read"},
    ],
)
def test_invalid_condition_types_fail_closed(service, condition):
    policies = json.loads(service.policy_path.read_text())
    policies[0]["conditions"] = [condition]
    service.policy_path.write_text(json.dumps(policies))
    assert service.evaluate(AccessRequest.model_validate(BASE))["reason_code"] == "INVALID_POLICY"


def test_same_size_same_timestamp_policy_edit_invalidates_cache(service):
    request = AccessRequest.model_validate(BASE)
    first = service.evaluate(request)
    original_stat = service.policy_path.stat()
    content = service.policy_path.read_text()
    assert '"priority": 10' in content
    service.policy_path.write_text(content.replace('"priority": 10', '"priority": 99', 1))
    os.utime(service.policy_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    second = service.evaluate(request)
    assert first["trace"]["catalogue_digest"] != second["trace"]["catalogue_digest"]
    service.policy_path.unlink()
    assert service.evaluate(request)["reason_code"] == "INVALID_POLICY"


@pytest.mark.parametrize("name", ["users", "resources"])
def test_duplicate_attribute_identity_rejected(service, name):
    path = service.provider.root / f"{name}.json"
    rows = json.loads(path.read_text())
    rows.append(deepcopy(rows[0]))
    path.write_text(json.dumps(rows))
    result = service.evaluate(AccessRequest.model_validate(BASE))
    assert result["decision_status"] == "DENIED_DUE_TO_TECHNICAL_FAILURE"


@pytest.mark.parametrize("timestamp", [None, 123, [], {}, "not-a-date"])
def test_malformed_timestamp_has_explicit_denial(service, timestamp):
    path = service.provider.root / "users.json"
    rows = json.loads(path.read_text())
    for row in rows:
        row["timestamp"] = timestamp
    path.write_text(json.dumps(rows))
    assert (
        service.evaluate(AccessRequest.model_validate(BASE))["reason_code"] == "INVALID_ATTRIBUTE"
    )


def test_lost_opa_catalogue_denies_then_recovers(service):
    request = AccessRequest.model_validate(BASE)
    first = service.evaluate(request)
    digest = first["trace"]["catalogue_digest"]
    service.opa.client.delete(f"/v1/data/capstone_catalogues/{digest}").raise_for_status()
    missing = service.evaluate(request)
    assert missing["decision"] == "DENY"
    assert missing["reason_code"] == "UNDEFINED_POLICY_RESULT"
    assert service.evaluate(request)["decision"] == "ALLOW"


def test_concurrent_requests_publish_catalogue_once(service, monkeypatch):
    calls = []
    original = service.opa.client.put

    def publish(*args, **kwargs):
        calls.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(service.opa.client, "put", publish)
    request = AccessRequest.model_validate(BASE)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: service.evaluate(request), range(16)))
    assert len(calls) == 1
    assert all(result["decision"] == "ALLOW" for result in results)


@pytest.mark.parametrize("compact", [False, True])
def test_inline_and_cached_opa_results_identical(service, compact):
    request = AccessRequest.model_validate(BASE)
    attributes = service.provider.resolve(request, datetime.now(timezone.utc), True)["attributes"]
    policies = service.repository.load(service.policy_path)
    cached = service.opa.evaluate(attributes, "context_abac", policies, "none", compact=compact)
    service.opa.cache_catalogues = False
    inline = service.opa.evaluate(attributes, "context_abac", policies, "none", compact=compact)
    assert cached == inline


def test_publish_failure_never_grants(service, monkeypatch):
    def unavailable(*args, **kwargs):
        raise httpx.ConnectError("unavailable")

    monkeypatch.setattr(service.opa.client, "put", unavailable)
    result = service.evaluate(AccessRequest.model_validate(BASE))
    assert result["decision"] == "DENY"
    assert result["reason_code"] == "OPA_UNAVAILABLE"


@pytest.mark.parametrize("passed", [[], [1], ["true"], None])
def test_compact_malformed_booleans_rejected(service, passed):
    policies = service.repository.load(service.policy_path)[:1]
    rows = [{"id": policies[0]["id"], "target_match": True, "outcome": "Permit", "passed": passed}]
    with pytest.raises(ValueError):
        validate_outcomes(expand_compact(rows, policies, "context_abac"), policies, "context_abac")


@pytest.mark.parametrize(
    "content", ['{"role":"admin","role":"intern"}', '{"x":NaN}', '{"x":Infinity}']
)
def test_ambiguous_json_rejected(content):
    with pytest.raises(ValueError):
        strict_json_loads(content)


@pytest.mark.parametrize("count", [10, 100, 500, 1000, 5000])
def test_full_and_compact_match_every_outcome_at_scale(service, count):
    policies = generate(count)
    attributes = {
        "resource": {"id": "benchmark_control"},
        "action": "read",
        "context": {"risk_score": 20, "location": "office"},
    }
    for missing in (False, True):
        if missing:
            del attributes["context"]["risk_score"]
        full = service.opa.evaluate(attributes, "context_abac", policies, "none")
        compact = service.opa.evaluate(attributes, "context_abac", policies, "none", compact=True)
        assert full == compact


def test_malformed_server_context_with_injection_is_denied(service):
    (service.provider.root / "contexts.json").write_text('{"engineer": []}')
    request = {key: value for key, value in BASE.items() if key != "context"}
    request["failure_mode"] = "missing_attribute"
    result = service.evaluate(AccessRequest.model_validate(request))
    assert result["decision"] == "DENY"
    assert result["reason_code"] == "INVALID_ATTRIBUTE"
