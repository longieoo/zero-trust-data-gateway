"""Exercise the live HTTP demo and save independently specified expectations."""

import json
import os
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "Trusted low-risk workday": "ALLOW",
    "Untrusted device": "DENY",
    "High risk": "DENY",
    "Outside work hours": "DENY",
    "Unexpected location": "DENY",
    "Untrusted and high risk": "DENY",
    "Medium risk": "ALLOW",
}


def main():
    records = []
    with httpx.Client(
        base_url=os.getenv("API_URL", "http://127.0.0.1:8000"), timeout=15, trust_env=False
    ) as client:
        health = client.get("/health").json()
        assert health["opa_ready"] and health["simulation"] and health["failure_injection"]
        scenarios = client.get("/scenarios").json()
        assert {s["name"] for s in scenarios} == set(EXPECTED)
        for scenario in scenarios:
            for baseline in ("rbac", "static_abac", "context_abac"):
                expected = EXPECTED[scenario["name"]] if baseline == "context_abac" else "ALLOW"
                result = client.post(
                    "/evaluate", json={**scenario["request"], "baseline": baseline}
                ).json()
                records.append(
                    {
                        "name": scenario["name"],
                        "baseline": baseline,
                        "expected": expected,
                        "actual": result["decision"],
                        "reason": result["reason_code"],
                        "pass": result["decision"] == expected,
                        "trace": result["trace"],
                    }
                )
        base = scenarios[0]["request"]
        for failure in (
            "opa_unavailable",
            "provider_unavailable",
            "stale_attribute",
            "invalid_opa_response",
        ):
            result = client.post("/protected", json={**base, "failure_mode": failure}).json()
            authorization = result["authorization"]
            records.append(
                {
                    "name": failure,
                    "expected": "DENY",
                    "actual": authorization["decision"],
                    "reason": authorization["reason_code"],
                    "pass": result["resource"] is None
                    and authorization["decision"] == "DENY"
                    and authorization["decision_status"] == "DENIED_DUE_TO_TECHNICAL_FAILURE",
                }
            )
        malformed = client.post("/evaluate", json={**base, "action": "execute"})
        records.append(
            {
                "name": "malformed_request",
                "expected": "DENY",
                "actual": malformed.json()["decision"],
                "pass": malformed.status_code == 422 and malformed.json()["decision"] == "DENY",
            }
        )
    path = Path(os.getenv("DEMO_RESULTS", str(ROOT / "report_assets/live-demo-results.json")))
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    assert all(row["pass"] for row in records), "See live-demo-results.json for failures"
    print(f"{len(records)} live HTTP demo assertions passed")


if __name__ == "__main__":
    main()
