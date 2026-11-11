"""Predetermined expectations, authored before implementation execution.

Cases use shared business inputs. Mutations are test fixtures, never client policies.
"""

BASE = {
    "subject_id": "engineer",
    "resource_id": "production_db",
    "action": "read",
    "baseline": "context_abac",
    "strategy": "deny-overrides",
    "context": {
        "device_trusted": True,
        "location": "office",
        "time": "2026-01-15T10:00:00Z",
        "risk_score": 20,
    },
}

# description, request changes, context changes, fixture, expected decision, expected reason
SPECS = [
    ("RBAC normal read", {"baseline": "rbac"}, {}, None, "ALLOW", "ROLE_PERMISSION"),
    (
        "Role action restriction",
        {"subject_id": "risk", "action": "write", "baseline": "rbac"},
        {},
        None,
        "DENY",
        "NO_APPLICABLE_PERMIT",
    ),
    (
        "Intern public report",
        {"subject_id": "intern", "resource_id": "public_report"},
        {},
        None,
        "ALLOW",
        "INTERN_REPORT",
    ),
    (
        "Static department restriction",
        {"resource_id": "risk_dataset", "baseline": "static_abac"},
        {},
        None,
        "DENY",
        "DEPARTMENT_MISMATCH",
    ),
    (
        "Static clearance restriction",
        {"subject_id": "marketing", "resource_id": "customer_dataset", "baseline": "static_abac"},
        {},
        None,
        "DENY",
        "INSUFFICIENT_CLEARANCE",
    ),
    ("Context normal access", {}, {}, None, "ALLOW", "ROLE_PERMISSION"),
    ("Untrusted device", {}, {"device_trusted": False}, None, "DENY", "UNTRUSTED_DEVICE"),
    ("High synthetic risk", {}, {"risk_score": 90}, None, "DENY", "HIGH_RISK"),
    ("Before working hours", {}, {"time": "2026-01-15T07:59:00Z"}, None, "DENY", "OUTSIDE_HOURS"),
    ("At closing hour", {}, {"time": "2026-01-15T18:00:00Z"}, None, "DENY", "OUTSIDE_HOURS"),
    ("Unexpected location", {}, {"location": "external"}, None, "DENY", "UNEXPECTED_LOCATION"),
    (
        "Missing context attribute",
        {"failure_mode": "missing_attribute"},
        {},
        None,
        "DENY",
        "MISSING_ATTRIBUTE",
    ),
    ("TTL exactly at expiration boundary", {}, {}, "ttl_boundary", "DENY", "STALE_ATTRIBUTE"),
    ("Unknown subject", {"subject_id": "unknown"}, {}, None, "DENY", "UNKNOWN_SUBJECT"),
    ("Unknown resource", {"resource_id": "unknown"}, {}, None, "DENY", "UNKNOWN_RESOURCE"),
    ("No matching policy", {}, {}, "empty", "DENY", "NO_APPLICABLE_PERMIT"),
    (
        "No applicable Permit",
        {"subject_id": "intern", "baseline": "rbac"},
        {},
        None,
        "DENY",
        "NO_APPLICABLE_PERMIT",
    ),
    ("Conflict deny overrides", {}, {"device_trusted": False}, None, "DENY", "UNTRUSTED_DEVICE"),
    (
        "Same conflict permit overrides",
        {"strategy": "permit-overrides"},
        {"device_trusted": False},
        None,
        "ALLOW",
        "ROLE_PERMISSION",
    ),
    (
        "Same conflict priority based",
        {"strategy": "priority-based"},
        {"device_trusted": False},
        None,
        "DENY",
        "UNTRUSTED_DEVICE",
    ),
    (
        "Equal priority Deny wins",
        {"strategy": "priority-based"},
        {"device_trusted": False},
        "equal",
        "DENY",
        "UNTRUSTED_DEVICE",
    ),
    (
        "Reversed policy ordering",
        {},
        {"device_trusted": False},
        "reverse",
        "DENY",
        "UNTRUSTED_DEVICE",
    ),
    ("OPA unavailable", {"failure_mode": "opa_unavailable"}, {}, None, "DENY", "OPA_UNAVAILABLE"),
    (
        "Provider unavailable",
        {"failure_mode": "provider_unavailable"},
        {},
        None,
        "DENY",
        "PROVIDER_UNAVAILABLE",
    ),
    ("Malformed request", {"action": "execute"}, {}, None, "DENY", "MALFORMED_REQUEST"),
    ("Invalid policy operator", {}, {}, "invalid", "DENY", "INVALID_POLICY"),
    (
        "Invalid OPA response",
        {"failure_mode": "invalid_opa_response"},
        {},
        None,
        "DENY",
        "INVALID_OPA_RESPONSE",
    ),
    ("Risk exactly at threshold", {}, {"risk_score": 70}, None, "DENY", "HIGH_RISK"),
]

CASES = [
    {
        "test_id": f"TC{i:02}",
        "description": description,
        "input": {**BASE, **changes, "context": {**BASE["context"], **context}},
        "fixture": fixture,
        "expected_result": decision,
        "expected_reason": reason,
    }
    for i, (description, changes, context, fixture, decision, reason) in enumerate(SPECS, 1)
]
