"""Orchestrates the visible decision pipeline without duplicating Rego conditions."""

import os
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from app.attribute_provider import AttributeProvider, DecisionError
from app.decision import combine
from app.models import AccessRequest
from app.opa_client import OPAClient
from app.policy_repository import PolicyRepository

ROOT = Path(__file__).resolve().parents[1]


def load_policies(path: Path) -> list:
    return PolicyRepository().load(path)


class DecisionService:
    def __init__(self, root: Path = ROOT):
        self.provider = AttributeProvider(Path(os.getenv("ATTRIBUTE_DIR", str(root / "data"))))
        self.repository = PolicyRepository()
        self.policy_path = Path(os.getenv("POLICY_FILE", str(root / "policies/policies.json")))
        self.opa = OPAClient(
            os.getenv("OPA_URL", "http://127.0.0.1:8181"), float(os.getenv("OPA_TIMEOUT", "5"))
        )
        self.simulation = os.getenv("SIMULATION_MODE", "0") == "1"
        self.dev_failures = os.getenv("DEV_FAILURES", "0") == "1"

    def evaluate(
        self, request: AccessRequest, now: datetime | None = None, trusted_provider=None
    ) -> dict:
        started = perf_counter()
        now = now or datetime.now(timezone.utc)
        request_id = str(uuid4())
        trace = {
            "request_id": request_id,
            "timestamp": now.isoformat(),
            "baseline": request.baseline,
            "strategy": request.strategy,
            "action": request.action,
            "stages": ["request_validated"],
            "candidate_policies": [],
            "applicable_policies": [],
            "policy_outcomes": [],
        }
        opa_ms = 0.0
        opa_eval_ms = 0.0
        try:
            if request.failure_mode != "none" and not self.dev_failures:
                raise DecisionError(
                    "FAILURE_INJECTION_DISABLED", "Development failure injection is disabled."
                )
            resolved = (trusted_provider or self.provider).resolve(request, now, self.simulation)
            trace.update(resolved)
            trace["stages"] += ["attributes_resolved", "freshness_validated"]
            policies = self.repository.load(self.policy_path)
            trace["catalogue_digest"] = policies.digest
            tick = perf_counter()
            outcomes, opa_eval_ms = self.opa.evaluate(
                resolved["attributes"],
                request.baseline,
                policies,
                request.failure_mode,
                measured=True,
                compact=not request.trace,
            )
            opa_ms = (perf_counter() - tick) * 1000
            trace["candidate_policies"] = [p["id"] for p in outcomes if p["target_match"]]
            trace["applicable_policies"] = [
                p["id"] for p in outcomes if p["outcome"] in ("Permit", "Deny")
            ]
            trace["policy_outcomes"] = outcomes
            trace["policy_versions"] = {p["id"]: p["version"] for p in outcomes}
            trace["stages"] += ["policies_matched", "conditions_evaluated", "outcomes_produced"]
            result = combine(outcomes, request.strategy)
            trace["stages"] += ["conflicts_detected", "strategy_applied", "final_decision"]
        except DecisionError as exc:
            trace["failure"] = {"reason_code": exc.code, "evidence": exc.evidence}
            result = {
                "decision": "DENY",
                "decision_status": "DENIED_DUE_TO_TECHNICAL_FAILURE"
                if exc.technical
                else "DENIED_BY_POLICY",
                "reason_code": exc.code,
                "explanation": exc.explanation,
                "effective_policies": [],
                "winning_policies": [],
                "conflict": False,
                "combining_rule": "fail-closed" if exc.technical else "deny-by-default",
            }
            trace["stages"].append("failed_closed")
        trace.update(result)
        trace["stages"].append("trace_generated")
        return {
            "request_id": request_id,
            "timestamp": now.isoformat(),
            "baseline": request.baseline,
            "strategy": request.strategy,
            **result,
            "trace": trace if request.trace else None,
            "metrics": {
                "opa_roundtrip_ms": opa_ms,
                "opa_eval_ms": opa_eval_ms,
                "service_ms": (perf_counter() - started) * 1000,
                "candidate_count": len(trace["candidate_policies"]),
                "matched_count": len(trace["applicable_policies"]),
            },
        }
