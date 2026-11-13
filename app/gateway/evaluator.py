"""One OPA transaction yields rule outcomes and candidate obligations from one release."""

from time import perf_counter

import httpx

from app.attribute_provider import DecisionError
from app.decision import combine
from app.gateway.database import COLUMNS, ViewPlan
from app.jsonio import strict_json_loads
from app.opa_client import validate_outcomes


def evaluate_snapshot(client, attributes, release):
    payload = release["payload"]
    inputs = {
        "attributes": attributes,
        "baseline": "context_abac",
        "policies": payload["policies"],
        "view": payload["view"],
        "revision": release["revision"],
        "engine_revision": payload["engine_revision"],
    }
    started = perf_counter()
    try:
        response = client.post("/v1/data/gateway/evaluation?metrics=true", json={"input": inputs})
        response.raise_for_status()
        if len(response.content) > 8_000_000:
            raise ValueError("Oversized decision envelope")
        body = strict_json_loads(response.text)
        if not isinstance(body, dict) or not isinstance(body.get("result"), dict):
            raise ValueError("Invalid decision envelope")
        result = body["result"]
        if set(result) != {"revision", "engine_revision", "outcomes", "plan", "contract"}:
            raise ValueError("Invalid decision envelope")
        if (
            result["revision"] != release["revision"]
            or result["engine_revision"] != payload["engine_revision"]
            or result["contract"] != "gateway-5.0.0"
        ):
            raise ValueError("Mismatched policy revision")
        validate_outcomes(result["outcomes"], payload["policies"], "context_abac")
        decision = combine(result["outcomes"], "deny-overrides")
        plan = ViewPlan.model_validate(result["plan"])
        subject = attributes["subject"]
        if plan.tenant_id != subject["tenant_id"] or plan.resource != attributes["resource"]["id"]:
            raise ValueError("Mismatched tenant/resource obligations")
        if plan.policy_revision != release["revision"]:
            raise ValueError("Mismatched obligation revision")
        # A matching revision label alone does not prove that the obligations
        # correspond to the signed profile. Enforce the complete supported
        # obligation contract independently before executing the plan.
        expected_scope = "all" if subject["role"] == "admin" else "department"
        expected_department = None if expected_scope == "all" else subject["department"]
        if (plan.row_scope.kind, plan.row_scope.value) != (expected_scope, expected_department):
            raise ValueError("Mismatched department obligations")
        expected_mask = (
            {"salary", "email", "national_id"}
            if plan.resource == "customers"
            and (subject["role"] != "admin" or payload["view"]["mask_admin"])
            else set()
        )
        if set(plan.mask) != expected_mask:
            raise ValueError("Mask differs from signed view profile")
        if plan.limit != payload["view"]["limit"]:
            raise ValueError("Row cap differs from signed view profile")
        if set(plan.columns) != COLUMNS[plan.resource]:
            raise ValueError("Incomplete resource column contract")
        return {
            **decision,
            "policy_revision": release["revision"],
            "engine_revision": payload["engine_revision"],
            "obligations": plan.model_dump() if decision["decision"] == "ALLOW" else None,
            "metrics": {
                "opa_roundtrip_ms": (perf_counter() - started) * 1000,
                "opa_eval_ms": body.get("metrics", {}).get("timer_rego_query_eval_ns", 0) / 1e6,
            },
        }
    except httpx.TimeoutException as exc:
        raise DecisionError("OPA_TIMEOUT", "OPA deadline exceeded") from exc
    except httpx.HTTPError as exc:
        raise DecisionError("OPA_UNAVAILABLE", "OPA unavailable") from exc
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise DecisionError(
            "INVALID_OPA_RESPONSE", "Invalid decision and obligation envelope"
        ) from exc


def semantic(result):
    return {
        key: result.get(key)
        for key in ("decision", "reason_code", "winning_policies", "obligations")
    }


def compare(before, after):
    changes = []
    if before["decision"] != after["decision"]:
        changes.append(before["decision"] + "->" + after["decision"])
    left, right = before.get("obligations") or {}, after.get("obligations") or {}
    for key in ("mask", "row_scope", "tenant_id", "limit", "columns"):
        if left.get(key) != right.get(key):
            changes.append(key.upper() + "_CHANGED")
    if before.get("reason_code") != after.get("reason_code"):
        changes.append("REASON_CHANGED")
    return changes or ["UNCHANGED"]
