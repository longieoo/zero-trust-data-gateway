"""Explicitly publish fresh synthetic snapshots; never refresh during lookup."""

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def seed():
    now = datetime.now(timezone.utc).isoformat()

    def envelope(attributes, ttl=86400):
        return {
            "attributes": attributes,
            "source": "synthetic-server-snapshot",
            "timestamp": now,
            "ttl_seconds": ttl,
        }

    users = [
        ("admin", "admin", "data", "restricted"),
        ("engineer", "data_engineer", "data", "restricted"),
        ("risk", "risk_analyst", "risk", "confidential"),
        ("marketing", "marketing_analyst", "marketing", "internal"),
        ("intern", "intern", "data", "public"),
    ]
    resources = [
        ("public_report", "report", "marketing", "public"),
        ("customer_dataset", "dataset", "marketing", "confidential"),
        ("risk_dataset", "dataset", "risk", "confidential"),
        ("production_db", "database", "data", "restricted"),
        ("finance_records", "records", "finance", "restricted"),
    ]
    write(
        "data/users.json",
        [envelope(dict(zip(("id", "role", "department", "clearance"), row))) for row in users],
    )
    write(
        "data/resources.json",
        [
            envelope(dict(zip(("id", "type", "department", "sensitivity"), row)))
            for row in resources
        ],
    )
    context = {
        "device_trusted": True,
        "location": "office",
        "time": "2026-01-15T10:00:00Z",
        "risk_score": 20,
    }
    write("data/contexts.json", {row[0]: envelope(context.copy(), 3600) for row in users})
    scenarios = []
    variants = [
        ("Trusted low-risk workday", {}),
        ("Untrusted device", {"device_trusted": False}),
        ("High risk", {"risk_score": 90}),
        ("Outside work hours", {"time": "2026-01-15T22:00:00Z"}),
        ("Unexpected location", {"location": "external"}),
        ("Untrusted and high risk", {"device_trusted": False, "risk_score": 90}),
        ("Medium risk", {"risk_score": 50}),
    ]
    for label, change in variants:
        scenarios.append(
            {
                "name": label,
                "request": {
                    "subject_id": "engineer",
                    "resource_id": "production_db",
                    "action": "read",
                    "baseline": "context_abac",
                    "strategy": "deny-overrides",
                    "context": {**context, **change},
                },
            }
        )
    write("data/scenarios.json", scenarios)


if __name__ == "__main__":
    seed()
