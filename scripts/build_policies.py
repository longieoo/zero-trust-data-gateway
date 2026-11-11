"""Human-sized policy catalogue shared by all three experimental baselines."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def condition(path, op, value=None, other=None):
    item = {"path": path.split("."), "op": op}
    item.update({"other": other.split(".")} if other else {"value": value})
    return item


def build():
    all_models = ["rbac", "static_abac", "context_abac"]
    static = ["static_abac", "context_abac"]
    context = ["context_abac"]
    policies = []

    def add(identifier, description, target, conditions, effect, priority, reason, baselines):
        policies.append(
            {
                "id": identifier,
                "description": description,
                "target": target,
                "conditions": conditions,
                "effect": effect,
                "priority": priority,
                "version": "1.0.0",
                "reason_code": reason,
                "baselines": baselines,
                "rationale": description,
            }
        )

    add(
        "P01",
        "The role grants this action.",
        [],
        [
            condition(
                "subject.role",
                "in",
                ["admin", "data_engineer", "risk_analyst", "marketing_analyst"],
            ),
            condition("action", "eq", "read"),
        ],
        "Permit",
        10,
        "ROLE_PERMISSION",
        all_models,
    )
    add(
        "P02",
        "Administrators and engineers may write.",
        [],
        [
            condition("subject.role", "in", ["admin", "data_engineer"]),
            condition("action", "eq", "write"),
        ],
        "Permit",
        10,
        "WRITE_PERMISSION",
        all_models,
    )
    add(
        "P03",
        "Only administrators may delete.",
        [],
        [condition("subject.role", "eq", "admin"), condition("action", "eq", "delete")],
        "Permit",
        10,
        "ADMIN_DELETE",
        all_models,
    )
    add(
        "P04",
        "Interns may read public reports.",
        [condition("subject.role", "eq", "intern"), condition("resource.type", "eq", "report")],
        [condition("action", "eq", "read")],
        "Permit",
        10,
        "INTERN_REPORT",
        all_models,
    )
    nonpublic = [condition("resource.sensitivity", "neq", "public")]
    add(
        "P05",
        "Non-public resources require the same department (administrators excepted).",
        nonpublic,
        [
            condition("subject.role", "neq", "admin"),
            condition("subject.department", "neq", other="resource.department"),
        ],
        "Deny",
        80,
        "DEPARTMENT_MISMATCH",
        static,
    )
    add(
        "P06",
        "Subject clearance must meet resource sensitivity.",
        [],
        [condition("subject.clearance", "rank_lt", other="resource.sensitivity")],
        "Deny",
        90,
        "INSUFFICIENT_CLEARANCE",
        static,
    )
    add(
        "P07",
        "Deletion of production databases is explicitly prohibited.",
        [condition("resource.type", "eq", "database")],
        [condition("action", "eq", "delete")],
        "Deny",
        100,
        "PRODUCTION_DELETE_PROHIBITED",
        all_models,
    )
    add(
        "P08",
        "Non-public resources require a trusted device.",
        nonpublic,
        [condition("context.device_trusted", "eq", False)],
        "Deny",
        100,
        "UNTRUSTED_DEVICE",
        context,
    )
    add(
        "P09",
        "Non-public resources require office or VPN location.",
        nonpublic,
        [condition("context.location", "eq", "external")],
        "Deny",
        90,
        "UNEXPECTED_LOCATION",
        context,
    )
    add(
        "P10",
        "Non-public resources cannot be accessed before 08:00 UTC.",
        nonpublic,
        [condition("context.hour", "lt", 8)],
        "Deny",
        90,
        "OUTSIDE_HOURS",
        context,
    )
    add(
        "P11",
        "Non-public resources cannot be accessed at or after 18:00 UTC.",
        nonpublic,
        [condition("context.hour", "gte", 18)],
        "Deny",
        90,
        "OUTSIDE_HOURS",
        context,
    )
    add(
        "P12",
        "Synthetic risk at or above 70 prohibits access.",
        [],
        [condition("context.risk_score", "gte", 70)],
        "Deny",
        110,
        "HIGH_RISK",
        context,
    )
    path = ROOT / "policies/policies.json"
    path.write_text(json.dumps(policies, indent=2) + "\n", encoding="utf-8")
    for model in all_models:
        folder = ROOT / "policies" / model
        folder.mkdir(exist_ok=True)
        (folder / "README.md").write_text(
            f"# {model}\n\nPolicies are filtered by `baselines` in ../policies.json. The shared ../engine.rego evaluates them without duplicating policy logic.\n\nIDs: "
            + ", ".join(p["id"] for p in policies if model in p["baselines"])
            + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    build()
