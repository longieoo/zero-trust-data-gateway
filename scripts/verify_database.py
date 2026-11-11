"""Real runtime-role RLS, pool reuse, session-store isolation and backup checks.

Executed inside the local Gateway container; no external database port exposed.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psycopg

from app.gateway.audit import AuditStore
from app.gateway.security import decode_token, issue_token
from app.gateway.sessions import PostgresSessions


def main():
    checks = []

    def check(name, passed, evidence):
        checks.append({"name": name, "pass": bool(passed), "evidence": evidence})

    dependency_check = subprocess.run(
        [sys.executable, "-m", "pip", "check"], capture_output=True, text=True
    )
    check(
        "runtime package dependencies are consistent",
        dependency_check.returncode == 0,
        {"output": dependency_check.stdout.strip()},
    )

    with psycopg.connect(os.environ["DATABASE_URL"]) as db:
        count = db.execute("SELECT count(*) FROM customer_data").fetchone()[0]
        check("RLS missing context returns zero", count == 0, {"rows": count})
        db.execute("SELECT set_config('gateway.scope','all',true)")
        count = db.execute("SELECT count(*) FROM customer_data").fetchone()[0]
        check("RLS all-scope without tenant returns zero", count == 0, {"rows": count})
        db.execute("SELECT set_config('gateway.tenant_id','demo',true)")
        rows = db.execute("SELECT DISTINCT tenant_id FROM customer_data").fetchall()
        check(
            "restrictive tenant gate applies to unfiltered SELECT",
            rows == [("demo",)],
            {"tenants": rows},
        )
        db.execute(
            "SELECT set_config('gateway.scope','department',true),set_config('gateway.department','marketing',true)"
        )
        rows = db.execute("SELECT DISTINCT tenant_id, department FROM customer_data").fetchall()
        check("RLS tenant AND department", rows == [("demo", "marketing")], {"scope": rows})
        db.commit()
        count = db.execute("SELECT count(*) FROM customer_data").fetchone()[0]
        check("transaction-local context cleared on connection reuse", count == 0, {"rows": count})
        flags = db.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname IN ('customer_data','financial_records','production_logs')"
        ).fetchall()
        check(
            "all three protected tables FORCE RLS",
            len(flags) == 3 and all(a and b for a, b in flags),
            {"flags": flags},
        )
        privileges = db.execute(
            "SELECT has_table_privilege(current_user,'customer_data','SELECT'), has_table_privilege(current_user,'customer_data','INSERT'), has_table_privilege(current_user,'customer_data','UPDATE'), has_table_privilege(current_user,'customer_data','DELETE')"
        ).fetchone()
        check(
            "reader SELECT only",
            privileges == (True, False, False, False),
            {"select_insert_update_delete": privileges},
        )
    with psycopg.connect(os.environ["SESSION_DATABASE_URL"]) as db:
        privilege = db.execute(
            "SELECT has_table_privilege(current_user,'customer_data','SELECT')"
        ).fetchone()[0]
        check(
            "session role cannot read business data",
            privilege is False,
            {"customer_select": privilege},
        )
    first, second = (PostgresSessions(os.environ["SESSION_DATABASE_URL"]) for _ in range(2))
    claims = decode_token(
        issue_token("probe", os.environ["GATEWAY_JWT_SECRET"], 1, "A1"),
        os.environ["GATEWAY_JWT_SECRET"],
    )
    first.add(claims)
    was_active = second.active(claims)
    start = time.perf_counter()
    first.revoke(claims)
    inactive = not second.active(claims)
    elapsed = (time.perf_counter() - start) * 1000
    first.close()
    second.close()
    check(
        "two independent session clients observe revocation",
        was_active and inactive,
        {"revoke_and_read_ms": elapsed, "scope": "two_store_instances_not_two_gateway_replicas"},
    )
    store = AuditStore(os.environ["GATEWAY_AUDIT_FILE"], os.environ["GATEWAY_AUDIT_KEY"])
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "audit.sqlite"
        store.backup(target)
        restored = AuditStore(target, os.environ["GATEWAY_AUDIT_KEY"])
        original = store.list("demo")
        check(
            "live audit backup restores same event page",
            restored.ready() and original == restored.list("demo") and len(original) > 0,
            {"events_compared": len(original), "integrity_check": restored.ready()},
        )
    print(json.dumps(checks))
    if not all(row["pass"] for row in checks):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
