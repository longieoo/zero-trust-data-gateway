"""OPA transport and strict semantic validation of its outcome envelope."""

import hashlib
import json
import os
from threading import Lock

import httpx

from app.attribute_provider import DecisionError


class OPAClient:
    def __init__(self, url: str, timeout: float = 5):
        self.cache_catalogues = os.getenv("OPA_CATALOGUE_CACHE", "1") == "1"
        self._published = set()
        self._publish_lock = Lock()
        self.client = httpx.Client(
            base_url=url,
            timeout=timeout,
            trust_env=False,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=50),
        )

    def evaluate(
        self,
        attributes: dict,
        baseline: str,
        policies: list,
        mode: str,
        measured=False,
        compact=False,
    ):
        if mode == "opa_unavailable":
            raise DecisionError("OPA_UNAVAILABLE", "Injected OPA connection failure.")
        if mode == "opa_timeout":
            raise DecisionError("OPA_TIMEOUT", "Injected OPA timeout.")
        if mode == "invalid_policy":
            raise DecisionError("INVALID_POLICY", "Injected rejected policy bundle.")
        try:
            inputs = {"attributes": attributes, "baseline": baseline}
            if self.cache_catalogues:
                digest = (
                    getattr(policies, "digest", None)
                    or hashlib.sha256(json.dumps(policies, sort_keys=True).encode()).hexdigest()
                )
                with self._publish_lock:
                    if digest not in self._published:
                        published = self.client.put(
                            f"/v1/data/capstone_catalogues/{digest}",
                            json=policies,
                        )
                        published.raise_for_status()
                        self._published.add(digest)
                inputs["catalogue_digest"] = digest
            else:
                inputs["policies"] = policies
            response = self.client.post(
                f"/v1/data/capstone/{'compact_outcomes' if compact else 'outcomes'}?metrics=true",
                json={"input": inputs},
            )
            response.raise_for_status()
            payload = response.json()
            if mode == "invalid_opa_response":
                payload = {"result": "ALLOW"}
            if mode == "undefined_result":
                payload = {}
            if not isinstance(payload, dict) or "result" not in payload:
                # OPA restart loses in-memory catalogues. This request DENYs; the next republishes.
                with self._publish_lock:
                    self._published.clear()
                raise DecisionError("UNDEFINED_POLICY_RESULT", "OPA returned no defined result.")
            outcomes = payload["result"]
            if compact:
                outcomes = expand_compact(outcomes, policies, baseline)
            validate_outcomes(outcomes, policies, baseline)
            if measured:
                return outcomes, payload.get("metrics", {}).get("timer_rego_query_eval_ns", 0) / 1e6
            return outcomes
        except httpx.TimeoutException as exc:
            raise DecisionError("OPA_TIMEOUT", "OPA evaluation exceeded its deadline.") from exc
        except httpx.HTTPError as exc:
            raise DecisionError("OPA_UNAVAILABLE", "OPA request failed.") from exc
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise DecisionError(
                "INVALID_OPA_RESPONSE", "OPA returned an invalid outcome envelope."
            ) from exc


def expand_compact(rows, policies, baseline):
    """Attach trusted static metadata; boolean results still come exclusively from OPA."""
    expected = {p["id"]: p for p in policies if baseline in p["baselines"]}
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise ValueError("Missing or extra compact outcomes")
    expanded = []
    for row in rows:
        policy = expected[row["id"]]
        passed = row["passed"]
        if not isinstance(passed, list) or len(passed) != len(policy["conditions"]):
            raise ValueError("Missing compact condition results")
        if any(type(value) is not bool for value in passed):
            raise ValueError("Invalid compact boolean")
        expanded.append(
            {
                **{
                    key: policy[key]
                    for key in ("id", "description", "priority", "version", "reason_code")
                },
                "target_match": row["target_match"],
                "outcome": row["outcome"],
                "conditions": [
                    {"condition": condition, "passed": value}
                    for condition, value in zip(policy["conditions"], passed)
                ],
            }
        )
    return expanded


def validate_outcomes(outcomes, policies, baseline):
    expected = {p["id"]: p for p in policies if baseline in p["baselines"]}
    if not isinstance(outcomes, list) or len(outcomes) != len(expected):
        raise ValueError("Missing or extra outcomes")
    seen = set()
    for row in outcomes:
        policy = expected[row["id"]]
        if row["id"] in seen:
            raise ValueError("Duplicate outcome")
        seen.add(row["id"])
        for key in ("id", "description", "priority", "version", "reason_code"):
            if row[key] != policy[key] or type(row[key]) is not type(policy[key]):
                raise ValueError("Metadata mismatch")
        if type(row["target_match"]) is not bool or not isinstance(row["conditions"], list):
            raise ValueError("Invalid match data")
        if len(row["conditions"]) != len(policy["conditions"]):
            raise ValueError("Missing condition results")
        for condition, result in zip(policy["conditions"], row["conditions"]):
            if result.get("condition") != condition or type(result.get("passed")) is not bool:
                raise ValueError("Invalid condition")
        expected_outcome = (
            policy["effect"]
            if row["target_match"] and all(c["passed"] for c in row["conditions"])
            else "NotApplicable"
        )
        if row["outcome"] == "Indeterminate":
            continue  # Explicit evaluation failure is always fail-closed by the combiner.
        if row["outcome"] != expected_outcome:
            raise ValueError("Inconsistent outcome")
