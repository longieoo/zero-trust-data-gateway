"""Validate RLS as the actual least-privilege runtime role, without printing credentials."""

import json

from scripts.validate_gateway import ROOT
from scripts.validate_gateway_failures import compose


def main():
    code = """
import os, json, psycopg
records = []
with psycopg.connect(os.environ['DATABASE_URL']) as connection:
    flags = connection.execute("SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname IN ('customer_data','financial_records','production_logs') ORDER BY relname").fetchall()
    records.append({'name': 'all protected tables enable and force RLS', 'pass': len(flags) == 3 and all(row[1] and row[2] for row in flags), 'evidence': flags})
    count = connection.execute('SELECT count(*) FROM customer_data').fetchone()[0]
    records.append({'name': 'missing scope yields zero rows', 'pass': count == 0, 'rows': count})
    connection.execute("SELECT set_config('gateway.scope', 'department', true), set_config('gateway.department','marketing',true)")
    rows = connection.execute('SELECT department FROM customer_data').fetchall()
    records.append({'name': 'department scope protects query without WHERE', 'pass': len(rows) == 2 and all(row[0] == 'marketing' for row in rows), 'rows': len(rows)})
    connection.commit()
    count = connection.execute('SELECT count(*) FROM customer_data').fetchone()[0]
    records.append({'name': 'scope expires on commit and connection reuse', 'pass': count == 0, 'rows': count})
    connection.execute("SELECT set_config('gateway.scope','all',true)")
    count = connection.execute('SELECT count(*) FROM customer_data').fetchone()[0]
    records.append({'name': 'explicit all scope returns complete synthetic dataset', 'pass': count == 3, 'rows': count})
print(json.dumps(records))
"""
    result = compose("exec", "-T", "gateway", "python", "-c", code)
    records = json.loads(result.stdout)
    destination = ROOT / "report_assets/gateway-rls-v4.json"
    destination.write_text(json.dumps(records, indent=2), encoding="utf-8")
    assert all(record["pass"] for record in records), "RLS regression"
    print(f"{len(records)}/{len(records)} real PostgreSQL RLS checks passed")


if __name__ == "__main__":
    main()
