"""Scoped outage tests of this project's containers; always restore the stack."""

import json
import subprocess
import time

from scripts.validate_gateway import ROOT, client, login


def compose(*args):
    return subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            ".gateway/gateway.env",
            "-f",
            "compose.gateway.yml",
            "-p",
            "abac-v3",
            *args,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def main():
    runtime = ROOT / ".gateway"
    credentials = json.loads((runtime / "credentials.json").read_text())
    records = []
    with client(runtime, "company-device") as http:
        headers = login(http, credentials, "analyst")
        for service in ("opa", "postgres"):
            try:
                compose("stop", service)
                response = http.get("/api/v1/data/customers", headers=headers)
                passed = response.status_code == 503 and "data" not in response.json()
                records.append(
                    {
                        "name": f"{service} outage withholds all protected data",
                        "pass": passed,
                        "http_status": response.status_code,
                        "reason_code": response.json().get("reason_code"),
                    }
                )
                assert passed, service
            finally:
                compose("start", service)
                for attempt in range(30):
                    response = http.get("/api/v1/data/customers", headers=headers)
                    if response.status_code == 200:
                        break
                    time.sleep(0.3)
                else:
                    raise RuntimeError(f"{service} did not recover")
                records.append({"name": f"{service} recovery permits valid request", "pass": True})
    role = compose(
        "exec",
        "-T",
        "gateway",
        "python",
        "-c",
        "import os,psycopg,json; c=psycopg.connect(os.environ['DATABASE_URL']); "
        "r=c.execute(\"SELECT current_user,has_table_privilege(current_user,'customer_data','SELECT'),"
        "has_table_privilege(current_user,'customer_data','INSERT'),"
        "has_table_privilege(current_user,'customer_data','DELETE'),"
        '(SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user)").fetchone(); '
        "print(json.dumps(r)); c.close()",
    )
    result = json.loads(role.stdout)
    passed = result == ["gateway_reader", True, False, False, False]
    records.append(
        {
            "name": "runtime database role has only read privileges",
            "pass": passed,
            "evidence": result,
        }
    )
    assert passed
    (ROOT / "report_assets/gateway-failures-v4.json").write_text(
        json.dumps(records, indent=2), encoding="utf-8"
    )
    print(f"{len(records)}/{len(records)} real outage/recovery/DB-role checks passed")


if __name__ == "__main__":
    main()
