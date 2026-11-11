"""Deterministic synthetic two-tenant batch, idempotent upsert and SQL quality checks.

This is generated test data, not a real customer ingestion connector.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone

from scripts.portfolio import ROOT, compose


def seed(rows):
    if not 10 <= rows <= 100000:
        raise ValueError("Rows per tenant must be 10..100000")
    statement = f"""
BEGIN;
INSERT INTO customer_data(id,department,name,email,salary,national_id,tenant_id)
SELECT 10000 + tenant_index * 100000 + n,
       CASE WHEN n % 3 = 0 THEN 'risk' ELSE 'marketing' END,
       'Synthetic ' || tenant || ' customer ' || n,
       tenant || '-' || n || '@example.test', 30000 + n * 7,
       'SYNTH-' || tenant || '-' || n, tenant
FROM (VALUES (0,'demo'),(1,'beta')) AS t(tenant_index,tenant)
CROSS JOIN generate_series(1,{rows}) AS n
ON CONFLICT(id) DO UPDATE SET department=EXCLUDED.department,name=EXCLUDED.name,
 email=EXCLUDED.email,salary=EXCLUDED.salary,national_id=EXCLUDED.national_id,tenant_id=EXCLUDED.tenant_id;
COMMIT;
SELECT json_build_object('counts', (SELECT json_agg(x) FROM
 (SELECT tenant_id,department,count(*) AS rows FROM customer_data GROUP BY tenant_id,department ORDER BY tenant_id,department) x),
 'synthetic_rows',(SELECT count(*) FROM customer_data WHERE id BETWEEN 10001 AND {10000 + rows} OR id BETWEEN 110001 AND {110000 + rows}),
 'invalid_rows',(SELECT count(*) FROM customer_data WHERE tenant_id NOT IN ('demo','beta') OR email NOT LIKE '%@example.test' OR salary < 0),
 'fingerprint',(SELECT md5(string_agg(row_to_json(x)::text,'' ORDER BY id)) FROM (SELECT * FROM customer_data) x));
"""
    result = compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "-X",
        "-qAt",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        "gateway_owner",
        "-d",
        "gateway_db",
        input=statement,
        text=True,
        capture_output=True,
    )
    quality = json.loads(result.stdout.strip())
    if quality["synthetic_rows"] != rows * 2 or quality["invalid_rows"] != 0:
        raise AssertionError("Synthetic data quality gate failed")
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "deterministic_synthetic_v1",
        "rows_per_tenant": rows,
        "contract_version": 1,
        "pii_columns": ["salary", "email", "national_id"],
        "sql_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        "quality": quality,
    }
    path = ROOT / "evidence/seed-manifest.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=1000)
    seed(parser.parse_args().rows)
