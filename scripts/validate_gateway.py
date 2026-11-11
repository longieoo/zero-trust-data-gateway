"""End-to-end verification over real TLS, Nginx, OPA and PostgreSQL."""

import json
import ssl
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def client(runtime, device=None, base_url="https://127.0.0.1:28443"):
    context = ssl.create_default_context(cafile=str(runtime / "tls/ca.crt"))
    if device:
        context.load_cert_chain(runtime / f"tls/{device}.crt", runtime / f"tls/{device}.key")
    return httpx.Client(base_url=base_url, verify=context, timeout=15, trust_env=False)


def login(http, credentials, username):
    response = http.post(
        "/auth/login", json={"username": username, "password": credentials[username]}
    )
    response.raise_for_status()
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def main():
    runtime = ROOT / ".gateway"
    credentials = json.loads((runtime / "credentials.json").read_text())
    records = []

    def check(name, passed, evidence):
        records.append({"name": name, "pass": bool(passed), "evidence": evidence})
        assert passed, name

    with client(runtime, "company-device") as trusted:
        check(
            "gateway healthy",
            trusted.get("/health").status_code == 200,
            "OPA and obligations module ready",
        )
        headers = login(trusted, credentials, "analyst")
        response = trusted.get("/api/v1/data/customers", headers=headers)
        result = response.json()
        check(
            "registered certificate and identity allowed",
            response.status_code == 200,
            response.status_code,
        )
        check(
            "department filter executed in PostgreSQL",
            len(result["data"]) == 2
            and all(row["department"] == "marketing" for row in result["data"]),
            {"row_count": len(result["data"])},
        )
        check(
            "sensitive columns masked",
            all(
                row[key] == "REDACTED"
                for row in result["data"]
                for key in ("email", "salary", "national_id")
            ),
            result["obligations"],
        )
        check(
            "context from TLS and server",
            result["context"]["device_trusted"]
            and result["context"]["source"] == "verified TLS proxy + server clock",
            result["context"],
        )
        engineer = login(trusted, credentials, "engineer")
        production = trusted.get("/api/v1/data/production", headers=engineer)
        check(
            "engineer reads real production records",
            production.status_code == 200 and len(production.json()["data"]) == 1,
            production.status_code,
        )
        check(
            "department mismatch blocked",
            trusted.get("/api/v1/data/customers", headers=engineer).status_code == 403,
            "P05",
        )
        admin = login(trusted, credentials, "admin")
        full = trusted.get("/api/v1/data/customers", headers=admin).json()
        check(
            "administrator explicit full view",
            len(full["data"]) == 3 and full["data"][0]["email"] != "REDACTED",
            {"row_count": len(full["data"])},
        )
        check(
            "identity required",
            trusted.get("/api/v1/data/customers").status_code == 401,
            "401 without token",
        )
        check(
            "client override rejected",
            trusted.get(
                "/api/v1/data/customers?strategy=permit-overrides", headers=headers
            ).status_code
            == 422,
            "422",
        )
        check(
            "unknown resource rejected",
            trusted.get("/api/v1/data/unknown", headers=headers).status_code == 404,
            "404",
        )
        check(
            "password rejected",
            trusted.post(
                "/auth/login", json={"username": "analyst", "password": "wrong"}
            ).status_code
            == 401,
            "401",
        )
        check(
            "forged token rejected",
            trusted.get(
                "/api/v1/data/customers", headers={"Authorization": "Bearer invalid"}
            ).status_code
            == 401,
            "401",
        )
        check(
            "no simulation transport exposed",
            trusted.post("/evaluate", json={}).status_code == 404,
            "404",
        )
        check(
            "no caching protected responses",
            response.headers.get("cache-control") == "no-store",
            "no-store",
        )
        check(
            "UI delivered through TLS",
            trusted.get("/").status_code == 200
            and "Cổng truy cập dữ liệu" in trusted.get("/").text,
            "200 HTML",
        )
    with client(runtime) as untrusted:
        same_identity = login(untrusted, credentials, "analyst")
        response = untrusted.get(
            "/api/v1/data/customers",
            headers={
                **same_identity,
                "X-Gateway-Device-Verified": "SUCCESS",
                "X-Gateway-Device-Serial": "FAKE",
                "X-Forwarded-For": "127.0.0.1",
            },
        )
        check(
            "no client certificate denied despite spoofed headers",
            response.status_code == 403 and response.json()["reason_code"] == "UNTRUSTED_DEVICE",
            response.json(),
        )
    with client(runtime, "unregistered-device") as unenrolled:
        copied = unenrolled.get("/api/v1/data/customers", headers=headers)
        check(
            "copied JWT on another certificate rejected", copied.status_code == 401, copied.json()
        )
        own_headers = login(unenrolled, credentials, "analyst")
        response = unenrolled.get("/api/v1/data/customers", headers=own_headers)
        check(
            "CA-signed but unregistered certificate denied",
            response.status_code == 403 and response.json()["reason_code"] == "UNTRUSTED_DEVICE",
            response.json(),
        )

    path = runtime / "server/registry.json"
    original = path.read_text()
    try:
        registry = json.loads(original)
        for device in registry["devices"].values():
            device["enabled"] = False
        path.write_text(json.dumps(registry), encoding="utf-8")
        with client(runtime, "company-device") as revoked:
            response = revoked.get("/api/v1/data/customers", headers=headers)
            check(
                "device revocation enforced on next request",
                response.status_code == 403,
                response.json(),
            )
    finally:
        path.write_text(original, encoding="utf-8")
    with client(runtime, "company-device") as registered:
        check(
            "logout revokes server session",
            registered.post("/auth/logout", headers=headers).status_code == 200,
            "200",
        )
        check(
            "replay after logout rejected",
            registered.get("/api/v1/data/customers", headers=headers).status_code == 401,
            "401",
        )
    (ROOT / "report_assets/gateway-e2e-v4.json").write_text(
        json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(
        f"{len(records)}/{len(records)} real Gateway E2E checks passed; secrets are excluded from evidence."
    )


if __name__ == "__main__":
    main()
