"""Validate catalogue revisions once; never cache authorization decisions."""

import hashlib
from pathlib import Path
from threading import Lock

from app.attribute_provider import DecisionError
from app.jsonio import strict_json_loads

FIELD_TYPES = {
    ("subject", "tenant_id"): str,
    ("action",): str,
    **{("subject", key): str for key in ("id", "role", "department", "clearance")},
    **{("resource", key): str for key in ("id", "type", "department", "sensitivity")},
    ("context", "device_trusted"): bool,
    ("context", "location"): str,
    ("context", "time"): str,
    ("context", "risk_score"): int,
    ("context", "hour"): int,
}
LEVEL_FIELDS = {("subject", "clearance"), ("resource", "sensitivity")}


class Catalogue(list):
    """Internal read-only-by-convention policy snapshot with content identity."""

    def __init__(self, policies, digest):
        super().__init__(policies)
        self.digest = digest


def validate_policies(policies):
    if not isinstance(policies, list):
        raise ValueError("Catalogue must be an array")
    ids = set()
    for policy in policies:
        if not isinstance(policy, dict):
            raise ValueError("Policy must be an object")
        for key in ("id", "description", "version", "reason_code", "rationale"):
            if not isinstance(policy.get(key), str) or not policy[key].strip():
                raise ValueError("Missing policy metadata")
        if policy["id"] in ids or policy.get("effect") not in ("Permit", "Deny"):
            raise ValueError("Duplicate ID or invalid effect")
        ids.add(policy["id"])
        if type(policy.get("priority")) is not int:
            raise ValueError("Invalid priority")
        baselines = policy.get("baselines")
        if (
            not isinstance(baselines, list)
            or not baselines
            or any(
                baseline not in ("rbac", "static_abac", "context_abac") for baseline in baselines
            )
        ):
            raise ValueError("Invalid baselines")
        for group in ("target", "conditions"):
            if not isinstance(policy.get(group), list):
                raise ValueError("Conditions must be arrays")
            for condition in policy[group]:
                if not isinstance(condition, dict):
                    raise ValueError("Condition must be an object")
                if condition.get("op") not in ("eq", "neq", "in", "gte", "lt", "rank_lt"):
                    raise ValueError("Invalid operator")
                for key in ("path", "other"):
                    if key == "other" and key not in condition:
                        continue
                    path = condition.get(key)
                    if (
                        not isinstance(path, list)
                        or not path
                        or any(not isinstance(part, str) or not part for part in path)
                    ):
                        raise ValueError("Invalid attribute path")
                if ("value" in condition) == ("other" in condition):
                    raise ValueError("Exactly one comparison operand is required")
                if set(condition) - {"path", "op", "value", "other"}:
                    raise ValueError("Unknown condition field")
                left = tuple(condition["path"])
                kind = FIELD_TYPES.get(left)
                if kind is None:
                    raise ValueError("Unknown attribute path")
                op = condition["op"]
                if op in ("gte", "lt") and kind is not int:
                    raise ValueError("Ordering requires numeric attributes")
                if op == "rank_lt" and left not in LEVEL_FIELDS:
                    raise ValueError("Rank comparison requires classification attributes")
                if "other" in condition:
                    other = tuple(condition["other"])
                    if FIELD_TYPES.get(other) is not kind or op == "in":
                        raise ValueError("Incompatible attribute operands")
                    if op == "rank_lt" and other not in LEVEL_FIELDS:
                        raise ValueError("Invalid classification operand")
                if "value" in condition:
                    value = condition["value"]
                    op = condition["op"]
                    if value is None or (op == "in" and not isinstance(value, list)):
                        raise ValueError("Invalid comparison operand")
                    if op == "in":
                        if any(type(item) is not kind for item in value):
                            raise ValueError("Incompatible membership values")
                    elif type(value) is not kind:
                        raise ValueError("Incompatible comparison type")
                    if op in ("gte", "lt") and type(value) is not int:
                        raise ValueError("Numeric comparison requires an integer")
                    if op == "rank_lt" and value not in (
                        "public",
                        "internal",
                        "confidential",
                        "restricted",
                    ):
                        raise ValueError("Invalid classification")


class PolicyRepository:
    def __init__(self):
        self._lock = Lock()
        self._snapshot = None

    def load(self, path: Path) -> Catalogue:
        try:
            # Read bytes on every request: deletions and same-mtime edits cannot use stale cache.
            content = path.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            with self._lock:
                if self._snapshot is None or self._snapshot.digest != digest:
                    policies = strict_json_loads(content)
                    validate_policies(policies)
                    self._snapshot = Catalogue(policies, digest)
                return self._snapshot
        except (OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise DecisionError(
                "INVALID_POLICY", "The policy repository failed validation."
            ) from exc
