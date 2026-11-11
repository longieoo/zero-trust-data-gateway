"""Bounded CA-verified HTTPS benchmark; warmup separated, raw samples retained."""

import csv
import json
import math
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from scripts.portfolio import ROOT
from scripts.validate_portfolio import client, login


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)]


def main():
    samples, summaries = [], []
    with client() as connection:
        auth = login(connection, "analyst")

        def request(index, concurrency, phase):
            start = time.perf_counter()
            code, opa_ms, reason = 0, None, "TRANSPORT_FAILURE"
            try:
                response = connection.get("/api/v1/data/customers", headers=auth)
                code = response.status_code
                body = response.json()
                opa_ms = body.get("metrics", {}).get("opa_eval_ms")
                reason = body.get("reason_code", "UNKNOWN")
                valid = (
                    code == 200
                    and body["decision"] == "ALLOW"
                    and body["obligations"]["tenant_id"] == "demo"
                )
            except Exception:
                valid = False
            return {
                "index": index,
                "concurrency": concurrency,
                "phase": phase,
                "http": code,
                "latency_ms": (time.perf_counter() - start) * 1000,
                "opa_eval_ms": opa_ms,
                "valid": valid,
                "reason": reason,
            }

        for concurrency in (1, 5, 10):
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                samples.extend(pool.map(lambda i: request(i, concurrency, "warmup"), range(10)))
                start = time.perf_counter()
                rows = list(pool.map(lambda i: request(i, concurrency, "measured"), range(100)))
                elapsed = time.perf_counter() - start
            samples.extend(rows)
            times = [row["latency_ms"] for row in rows]
            summaries.append(
                {
                    "concurrency": concurrency,
                    "requests": len(rows),
                    "elapsed_seconds": elapsed,
                    "p50_ms": percentile(times, 0.50),
                    "p95_ms": percentile(times, 0.95),
                    "rps": len(rows) / elapsed,
                    "errors": sum(not row["valid"] for row in rows),
                    "opa_eval_p50_ms": percentile(
                        [r["opa_eval_ms"] for r in rows if r["opa_eval_ms"] is not None], 0.5
                    )
                    if any(r["opa_eval_ms"] is not None for r in rows)
                    else None,
                }
            )
        connection.post("/auth/logout", headers=auth).raise_for_status()
    output = ROOT / "evidence"
    output.mkdir(exist_ok=True)
    with (output / "benchmark-samples.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(samples[0]))
        writer.writeheader()
        writer.writerows(samples)
    result = {
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "measured_samples": 300,
        "warmup_samples": 30,
        "workload": "customers; analyst; TLS verified; 100-row cap; audit ON; shared PostgreSQL sessions",
        "percentile_method": "nearest rank",
        "limitations": "Single local host, closed-loop load, other projects may share CPU; no production capacity claim",
        "runs": summaries,
    }
    (output / "benchmark.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    if any(row["errors"] for row in summaries):
        raise SystemExit("Benchmark correctness gate failed")


if __name__ == "__main__":
    main()
