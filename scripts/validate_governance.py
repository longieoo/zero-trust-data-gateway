"""Live mTLS checks for approval gates, revocation, expiry and bound pagination.

Uses only the dedicated local demo Gateway. No credentials, tokens, cursors or
business rows are written to evidence. Existing records belonging to unrelated
purposes are never changed. Policy/tenant/device checks remain mandatory.
"""

import json
import time
from datetime import datetime, timezone

from scripts.portfolio import ROOT
from scripts.validate_portfolio import client, login

PURPOSE = "Governance validation: production log review"


def summary(response):
    body = response.json()
    # Explicit allowlist avoids leaking signed cursors or returned business rows.
    return {
        "http": response.status_code,
        **{
            key: body.get(key)
            for key in (
                "request_id",
                "decision",
                "reason_code",
                "db_queried",
                "status",
                "tenant_id",
                "expires_at",
                "approved_at",
                "revoked_at",
            )
        },
    }


def main():
    checks = []
    completed = False
    started = time.perf_counter()
    destination = ROOT / "evidence/governance.json"
    destination.parent.mkdir(exist_ok=True)

    def check(name, passed, evidence):
        checks.append({"name": name, "pass": bool(passed), "evidence": evidence})
        print(("PASS " if passed else "FAIL ") + name, flush=True)
        if not passed:
            raise AssertionError(name)

    identities = []
    created = []
    owner = None
    try:
        with client() as connection:
            try:
                engineer = login(connection, "engineer")
                owner = login(connection, "data_owner")
                beta = login(connection, "beta_admin")
                analyst = login(connection, "analyst")
                identities.extend((engineer, owner, beta, analyst))

                def submit(auth, seconds=900, resource="production"):
                    response = connection.post(
                        "/api/v1/access-requests",
                        headers=auth,
                        json={
                            "resource": resource,
                            "purpose": PURPOSE,
                            "duration_seconds": seconds,
                        },
                    )
                    check(
                        "access request accepted for verified identity",
                        response.status_code == 201,
                        summary(response),
                    )
                    request_id = response.json()["request_id"]
                    created.append(request_id)
                    return request_id

                # Make retries repeatable after an interrupted validation, without
                # revoking requests created for another purpose or another user.
                previous = connection.get("/api/v1/access-requests?limit=100", headers=owner)
                previous.raise_for_status()
                for record in previous.json()["requests"]:
                    if (
                        record["purpose"] == PURPOSE
                        and record["requester"] in {"engineer", "data_owner", "analyst"}
                        and record["status"] in {"PENDING", "APPROVED"}
                    ):
                        response = connection.post(
                            f"/api/v1/access-requests/{record['request_id']}/revoke", headers=owner
                        )
                        response.raise_for_status()

                denied = connection.get("/api/v1/data/production", headers=engineer)
                check(
                    "production read requires approval before SELECT",
                    denied.status_code == 403
                    and denied.json().get("reason_code") == "ACCESS_APPROVAL_REQUIRED"
                    and denied.json().get("db_queried") is False,
                    summary(denied),
                )

                request_id = submit(engineer)
                path = "/api/v1/access-requests/" + request_id
                denied = connection.post(path + "/approve", headers=engineer)
                check(
                    "requester cannot approve a request", denied.status_code == 403, summary(denied)
                )
                denied = connection.post(path + "/approve", headers=beta)
                check(
                    "other tenant admin cannot approve request",
                    denied.status_code == 404,
                    summary(denied),
                )
                own_request = submit(owner)
                denied = connection.post(
                    f"/api/v1/access-requests/{own_request}/approve", headers=owner
                )
                check("admin cannot self approve", denied.status_code == 403, summary(denied))

                approved = connection.post(path + "/approve", headers=owner)
                check(
                    "independent tenant owner approves",
                    approved.status_code == 200 and approved.json().get("status") == "APPROVED",
                    summary(approved),
                )
                allowed = connection.get("/api/v1/data/production", headers=engineer)
                check(
                    "approved engineer reads production under normal ABAC",
                    allowed.status_code == 200
                    and allowed.json().get("decision") == "ALLOW"
                    and allowed.json().get("db_queried") is True
                    and allowed.json()["obligations"]["tenant_id"] == "demo"
                    and allowed.json()["obligations"]["row_scope"]
                    == {"kind": "department", "value": "data"},
                    summary(allowed),
                )
                revoked = connection.post(path + "/revoke", headers=owner)
                check(
                    "owner revokes grant",
                    revoked.status_code == 200 and revoked.json().get("status") == "REVOKED",
                    summary(revoked),
                )
                denied = connection.get("/api/v1/data/production", headers=engineer)
                check(
                    "revoked grant denies next protected SELECT",
                    denied.status_code == 403
                    and denied.json().get("reason_code") == "ACCESS_APPROVAL_REQUIRED"
                    and denied.json().get("db_queried") is False,
                    summary(denied),
                )

                financial_id = submit(analyst, resource="financial")
                approved = connection.post(
                    f"/api/v1/access-requests/{financial_id}/approve", headers=owner
                )
                check(
                    "independent owner approves financial workflow record",
                    approved.status_code == 200 and approved.json().get("status") == "APPROVED",
                    summary(approved),
                )
                denied = connection.get("/api/v1/data/financial", headers=analyst)
                check(
                    "approved workflow cannot bypass an ABAC deny",
                    denied.status_code == 403
                    and denied.json().get("decision") == "DENY"
                    and denied.json().get("reason_code") != "ACCESS_APPROVAL_REQUIRED"
                    and denied.json().get("db_queried") is False,
                    summary(denied),
                )

                expiring_id = submit(engineer, 60)
                approved = connection.post(
                    f"/api/v1/access-requests/{expiring_id}/approve", headers=owner
                )
                check(
                    "short lived grant accepted",
                    approved.status_code == 200 and approved.json().get("status") == "APPROVED",
                    summary(approved),
                )
                expires_at = datetime.fromisoformat(approved.json()["expires_at"])
                approved_at = datetime.fromisoformat(approved.json()["approved_at"])
                # Wait the server-issued lifetime from receipt using a monotonic
                # timer. Client/server wall clocks can differ at a second boundary.
                expiry_deadline = time.monotonic() + (expires_at - approved_at).total_seconds() + 2

                first = connection.get("/api/v1/data/customers?page_size=25", headers=analyst)
                first_body = first.json()
                check(
                    "analyst first page enforces SQL masking and department",
                    first.status_code == 200
                    and len(first_body.get("data", [])) == 25
                    and all(
                        row["department"] == "marketing"
                        and all(
                            row[key] == "REDACTED" for key in ("salary", "email", "national_id")
                        )
                        for row in first_body["data"]
                    ),
                    {**summary(first), "rows": len(first_body.get("data", []))},
                )
                cursor = first_body["pagination"]["next_cursor"]
                check(
                    "first page provides continuation",
                    bool(cursor) and first_body["pagination"]["has_more"] is True,
                    {"has_more": first_body["pagination"]["has_more"]},
                )
                second = connection.get(
                    "/api/v1/data/customers",
                    headers=analyst,
                    params={"page_size": 25, "cursor": cursor},
                )
                body = second.json()
                check(
                    "second page has disjoint authorized rows",
                    second.status_code == 200
                    and len(body.get("data", [])) == 25
                    and not (
                        {row["id"] for row in first_body["data"]}
                        & {row["id"] for row in body["data"]}
                    )
                    and all(
                        row["department"] == "marketing"
                        and all(
                            row[key] == "REDACTED" for key in ("salary", "email", "national_id")
                        )
                        for row in body["data"]
                    ),
                    {**summary(second), "rows": len(body.get("data", [])), "disjoint": True},
                )
                # Modify the signed payload, not merely unused base64 padding bits.
                pieces = cursor.split(".")
                middle = len(pieces[1]) // 2
                pieces[1] = (
                    pieces[1][:middle]
                    + ("A" if pieces[1][middle] != "A" else "B")
                    + pieces[1][middle + 1 :]
                )
                tampered = ".".join(pieces)
                denied = connection.get(
                    "/api/v1/data/customers",
                    headers=analyst,
                    params={"page_size": 25, "cursor": tampered},
                )
                check(
                    "tampered cursor rejected before SELECT",
                    denied.status_code == 422
                    and denied.json().get("reason_code") == "INVALID_CURSOR"
                    and denied.json().get("db_queried") is False,
                    summary(denied),
                )
                denied = connection.get(
                    "/api/v1/data/customers",
                    headers=engineer,
                    params={"page_size": 25, "cursor": cursor},
                )
                check(
                    "cursor cannot move to another identity or session",
                    denied.status_code == 422 and denied.json().get("db_queried") is False,
                    summary(denied),
                )
                denied = connection.get(
                    "/api/v1/data/customers",
                    headers=beta,
                    params={"page_size": 25, "cursor": cursor},
                )
                check(
                    "cursor cannot move to another tenant",
                    denied.status_code == 422 and denied.json().get("db_queried") is False,
                    summary(denied),
                )

                print("Waiting for the server-issued 60-second grant to expire", flush=True)
                while time.monotonic() < expiry_deadline:
                    time.sleep(min(2, max(0.01, expiry_deadline - time.monotonic())))
                denied = connection.get("/api/v1/data/production", headers=engineer)
                check(
                    "real expiry denies next request before SELECT",
                    denied.status_code == 403
                    and denied.json().get("reason_code") == "ACCESS_APPROVAL_REQUIRED"
                    and denied.json().get("db_queried") is False,
                    {
                        **summary(denied),
                        "checked_at": datetime.now(timezone.utc).isoformat(),
                        "grant_expires_at": expires_at.isoformat(),
                    },
                )
                completed = True
            finally:
                if owner is not None:
                    for request_id in created:
                        try:
                            connection.post(
                                f"/api/v1/access-requests/{request_id}/revoke", headers=owner
                            )
                        except Exception:
                            pass
                for identity in identities:
                    try:
                        connection.post("/auth/logout", headers=identity)
                    except Exception:
                        pass
    finally:
        result = {
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "target": "CA-verified HTTPS local demo Gateway",
            "elapsed_seconds": time.perf_counter() - started,
            "complete": completed and all(row["pass"] for row in checks),
            "passed": sum(row["pass"] for row in checks),
            "checks": checks,
        }
        destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"{len(checks)}/{len(checks)} live governance checks passed", flush=True)


if __name__ == "__main__":
    main()
