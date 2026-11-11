"""Measure the permitted real Gateway path; retain errors and raw timings."""

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from benchmark.analyze import percentile
from scripts.validate_gateway import client, login, ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--output", type=Path, default=ROOT / "benchmark/results/gateway-v4")
    args = parser.parse_args()
    if args.samples <= 0 or args.warmup < 0:
        parser.error("samples must be positive; warmup cannot be negative")
    args.output.mkdir(parents=True, exist_ok=True)
    runtime = ROOT / ".gateway"
    credentials = json.loads((runtime / "credentials.json").read_text())
    rows = []
    with client(runtime, "company-device") as http:
        headers = login(http, credentials, "analyst")
        for index in range(args.warmup + args.samples):
            tick = perf_counter()
            status, error, correct, metrics = 0, 1, False, {}
            try:
                response = http.get("/api/v1/data/customers", headers=headers)
                status = response.status_code
                result = response.json()
                error = int(status != 200)
                data = result.get("data", [])
                correct = (
                    status == 200
                    and len(data) == 2
                    and all(
                        row["department"] == "marketing"
                        and all(
                            row[key] == "REDACTED" for key in ("email", "salary", "national_id")
                        )
                        for row in data
                    )
                )
                metrics = result.get("metrics", {})
            except Exception:
                pass
            rows.append(
                {
                    "sample": index,
                    "phase": "warmup" if index < args.warmup else "measurement",
                    "http_ms": (perf_counter() - tick) * 1000,
                    "status": status,
                    "error": error,
                    "correct": int(correct),
                    **{
                        key: metrics.get(key, 0)
                        for key in (
                            "opa_eval_ms",
                            "opa_roundtrip_ms",
                            "service_ms",
                            "obligation_ms",
                            "database_ms",
                            "gateway_ms",
                        )
                    },
                }
            )
    with (args.output / "raw.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    measured = rows[args.warmup :]
    successful = [row for row in measured if row["correct"]]
    summary = {
        "samples": len(measured),
        "errors": sum(row["error"] for row in measured),
        "correct": sum(row["correct"] for row in measured),
        "metrics": {},
    }
    for key in (
        "http_ms",
        "opa_eval_ms",
        "opa_roundtrip_ms",
        "service_ms",
        "obligation_ms",
        "database_ms",
        "gateway_ms",
    ):
        values = [row[key] for row in measured if key == "http_ms" or row in successful]
        summary["metrics"][key] = {"p50": percentile(values, 0.5), "p95": percentile(values, 0.95)}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2))
    (args.output / "environment.json").write_text(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "protocol": "Sequential TLS requests, same registered device and analyst, 3 source rows/2 permitted, masking in SQL",
                "warmup": args.warmup,
                "samples": args.samples,
                "repetitions": 1,
                "concurrency": 1,
                "limitations": "Pilot only. DB timings are nested in Gateway timing, not a separate direct-DB experiment. JWT verification included; login and TLS handshake not separately measured.",
            },
            indent=2,
        )
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
