"""Live HTTPS/CA-verified mTLS, signed release, replay, RLS and recovery evidence.

Mutates only the local abac-portfolio deployment. Always restores OPA and active
policy in finally blocks. Never prints passwords, tokens or signing keys.
"""

import json
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx
from cryptography.hazmat.primitives import serialization

from app.gateway.releases import ReleaseRepository, atomic_json, digest, sign_release
from scripts.portfolio import ROOT, RUNTIME, compose
from scripts.seed_portfolio import seed


def client(cert=True):
    context = ssl.create_default_context(cafile=str(RUNTIME / "tls/ca.crt"))
    if cert:
        context.load_cert_chain(
            RUNTIME / "tls/company-device.crt", RUNTIME / "tls/company-device.key"
        )
    return httpx.Client(
        base_url="https://127.0.0.1:28443", verify=context, trust_env=False, timeout=15
    )


def login(connection, user):
    credentials = json.loads((RUNTIME / "credentials.json").read_text())
    response = connection.post(
        "/auth/login", json={"username": user, "password": credentials[user]}
    )
    if response.status_code != 200:
        raise AssertionError(f"Login {user} HTTP {response.status_code}")
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def main():
    records = []
    completed = False
    destination = ROOT / "evidence/live-validation.json"
    destination.parent.mkdir(exist_ok=True)

    def check(name, passed, evidence):
        records.append({"name": name, "pass": bool(passed), "evidence": evidence})
        print(("PASS " if passed else "FAIL ") + name)
        if not passed:
            raise AssertionError(name)

    def summary(response):
        body = response.json()
        return {
            "http": response.status_code,
            **{
                key: body.get(key)
                for key in (
                    "request_id",
                    "decision",
                    "reason_code",
                    "db_queried",
                    "policy_revision",
                    "row_count",
                    "obligations",
                )
            },
        }

    repository = ReleaseRepository(
        RUNTIME / "server/releases", RUNTIME / "server/trusted-policy-keys.json"
    )
    baseline = repository.active()
    original_revision = baseline["revision"]
    started = time.perf_counter()
    try:
        first = seed(1000)
        second = seed(1000)
        check(
            "synthetic batch idempotence and quality",
            first["quality"] == second["quality"],
            second["quality"],
        )
        with client() as trusted, client(False) as untrusted:
            response = trusted.get("/health")
            check("CA verified TLS readiness", response.status_code == 200, response.json())
            analyst, admin, beta = (
                login(trusted, name) for name in ("analyst", "admin", "beta_admin")
            )
            outside = login(untrusted, "analyst")
            allowed = trusted.get("/api/v1/data/customers", headers=analyst)
            body = allowed.json()
            check(
                "analyst SQL masking and tenant department scope",
                allowed.status_code == 200
                and len(body["data"]) > 0
                and all(
                    row["department"] == "marketing"
                    and all(row[k] == "REDACTED" for k in ("salary", "email", "national_id"))
                    for row in body["data"]
                )
                and body["obligations"]["tenant_id"] == "demo",
                summary(allowed),
            )
            response = trusted.get("/api/v1/data/customers", headers=admin)
            check(
                "tenant admin can read unmasked within own tenant",
                response.status_code == 200
                and all(
                    row["id"] < 110000 and row["email"] != "REDACTED"
                    for row in response.json()["data"]
                ),
                summary(response),
            )
            response = trusted.get("/api/v1/data/customers", headers=beta)
            check(
                "second tenant admin cannot see first tenant",
                response.status_code == 200
                and all(row["id"] >= 110001 for row in response.json()["data"]),
                summary(response),
            )
            response = trusted.get(
                "/api/v1/data/customers", headers={**analyst, "X-Tenant-ID": "beta"}
            )
            check(
                "client tenant header cannot override identity",
                response.status_code == 200
                and response.json()["obligations"]["tenant_id"] == "demo",
                summary(response),
            )
            response = untrusted.get("/api/v1/data/customers", headers=outside)
            check(
                "unenrolled TLS client denied before SELECT",
                response.status_code == 403
                and response.json()["reason_code"] == "UNTRUSTED_DEVICE"
                and response.json()["db_queried"] is False,
                summary(response),
            )
            response = untrusted.get("/api/v1/data/customers", headers=analyst)
            check(
                "certificate-bound token cannot transfer",
                response.status_code == 401 and response.json()["db_queried"] is False,
                summary(response),
            )
            response = trusted.get("/api/v1/data/financial", headers=analyst)
            check(
                "ABAC department denial before SELECT",
                response.status_code == 403 and response.json()["db_queried"] is False,
                summary(response),
            )
            response = trusted.post(f"/api/v1/audit/{body['request_id']}/replay", headers=analyst)
            check(
                "historical decision replay matches",
                response.json()["status"] == "MATCH" and response.json()["db_queried"] is False,
                response.json(),
            )
            response = trusted.post(f"/api/v1/audit/{body['request_id']}/replay", headers=beta)
            check(
                "audit snapshot is tenant isolated",
                response.json()["status"] == "UNREPLAYABLE",
                response.json(),
            )
            candidate = json.loads(json.dumps(baseline))
            candidate["payload"]["view"]["mask_admin"] = True
            candidate["payload"]["description"] = (
                "Live test: apply PII masks to tenant administrators"
            )
            candidate["revision"] = digest(candidate["payload"])
            candidate["signatures"] = {}
            author = serialization.load_pem_private_key(
                (RUNTIME / "maintainers/author.pem").read_bytes(), None
            )
            reviewer = serialization.load_pem_private_key(
                (RUNTIME / "maintainers/reviewer.pem").read_bytes(), None
            )
            sign_release(candidate, "author", author)
            candidate_path = repository.directory / (candidate["revision"] + ".json")
            atomic_json(candidate_path, candidate)
            try:
                repository.activate(candidate["revision"], original_revision)
                blocked = False
            except ValueError:
                blocked = True
            check(
                "one signer cannot activate",
                blocked and repository.active()["revision"] == original_revision,
                {"active_unchanged": True},
            )
            response = trusted.post(
                "/api/v1/policies/impact",
                headers=admin,
                json={"revision": candidate["revision"], "limit": 30},
            )
            impact = response.json()
            check(
                "impact finds admin mask changes on historical snapshots",
                response.status_code == 200
                and any("MASK_CHANGED" in row.get("changes", []) for row in impact["records"]),
                impact,
            )
            sign_release(candidate, "reviewer", reviewer)
            atomic_json(candidate_path, candidate)
            repository.activate(candidate["revision"], original_revision)

            # Toggle immutable active pointers while independent requests execute.
            def rotate():
                current = candidate["revision"]
                for _ in range(6):
                    other = (
                        original_revision
                        if current == candidate["revision"]
                        else candidate["revision"]
                    )
                    repository.activate(other, current)
                    current = other
                    time.sleep(0.02)

            with ThreadPoolExecutor(max_workers=5) as pool:
                rotation = pool.submit(rotate)
                futures = [
                    pool.submit(trusted.get, "/api/v1/data/customers", headers=admin)
                    for _ in range(12)
                ]
                concurrent = [future.result() for future in futures]
                rotation.result()
            consistent = all(
                r.status_code == 200
                and r.json()["policy_revision"] == r.json()["obligations"]["policy_revision"]
                and (r.json()["data"][0]["email"] == "REDACTED")
                == (r.json()["policy_revision"] == candidate["revision"])
                for r in concurrent
            )
            check(
                "concurrent activation keeps decision and mask revision consistent",
                consistent,
                {
                    "requests": len(concurrent),
                    "observed_revisions": sorted(
                        {r.json().get("policy_revision", "missing") for r in concurrent}
                    ),
                },
            )
            response = trusted.get("/api/v1/data/customers", headers=admin)
            check(
                "two signed release activation changes obligations",
                response.status_code == 200
                and response.json()["policy_revision"] == candidate["revision"]
                and all(row["email"] == "REDACTED" for row in response.json()["data"]),
                summary(response),
            )
            tampered = json.loads(json.dumps(candidate))
            tampered["payload"]["view"]["mask_admin"] = False
            atomic_json(candidate_path, tampered)
            try:
                response = trusted.get("/api/v1/data/customers", headers=admin)
                check(
                    "tampered active release fails closed",
                    response.status_code == 503
                    and response.json()["reason_code"] == "INVALID_POLICY"
                    and response.json()["db_queried"] is False,
                    summary(response),
                )
            finally:
                atomic_json(candidate_path, candidate)
            repository.activate(original_revision, candidate["revision"])
            response = trusted.get("/api/v1/data/customers", headers=admin)
            check(
                "verified rollback restores original revision",
                response.status_code == 200
                and response.json()["policy_revision"] == original_revision
                and response.json()["data"][0]["email"] != "REDACTED",
                summary(response),
            )
            try:
                compose("stop", "opa", capture_output=True)
                response = trusted.get("/api/v1/data/customers", headers=analyst)
                check(
                    "OPA outage fail closed",
                    response.status_code == 503
                    and response.json()["reason_code"] == "OPA_UNAVAILABLE"
                    and response.json()["db_queried"] is False,
                    summary(response),
                )
            finally:
                compose("start", "opa", capture_output=True)
                for _ in range(30):
                    try:
                        if trusted.get("/health").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(1)
            response = trusted.get("/api/v1/data/customers", headers=analyst)
            check(
                "OPA restart recovers without authorization cache",
                response.status_code == 200,
                summary(response),
            )
            response = trusted.post("/auth/logout", headers=analyst)
            check(
                "logout revokes shared session",
                response.status_code == 200,
                {"http": response.status_code},
            )
            response = trusted.get("/api/v1/data/customers", headers=analyst)
            check(
                "replayed token rejected after logout",
                response.status_code == 401 and response.json()["db_queried"] is False,
                summary(response),
            )
        result = compose(
            "exec",
            "-T",
            "gateway",
            "python",
            "-m",
            "scripts.verify_database",
            capture_output=True,
            text=True,
        )
        checks = json.loads(result.stdout)
        for record in checks:
            check(record["name"], record["pass"], record["evidence"])
        completed = True
    finally:
        pointer = json.loads((repository.directory / "active.json").read_text())
        if pointer["revision"] != original_revision:
            repository.activate(original_revision, pointer["revision"])
        report = {
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "target": "local abac-portfolio",
            "elapsed_seconds": time.perf_counter() - started,
            "passed": sum(r["pass"] for r in records),
            "checks": records,
            "complete": completed and all(r["pass"] for r in records),
        }
        destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"{len(records)}/{len(records)} live checks passed")


if __name__ == "__main__":
    main()
