"""Repeated real HTTPS Gateway measurements with bounded concurrency and raw evidence."""

import argparse
import asyncio
import csv
import json
import ssl
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

import httpx

from benchmark.analyze import percentile
from scripts.validate_gateway import ROOT, client, login


async def run(args):
    runtime = ROOT / ".gateway"
    credentials = json.loads((runtime / "credentials.json").read_text())
    with client(runtime, "company-device") as http:
        headers = login(http, credentials, "analyst")
    tls = ssl.create_default_context(cafile=str(runtime / "tls/ca.crt"))
    tls.load_cert_chain(runtime / "tls/company-device.crt", runtime / "tls/company-device.key")
    args.output.mkdir(parents=True, exist_ok=True)
    rows, groups = [], []
    async with httpx.AsyncClient(
        base_url="https://127.0.0.1:28443", verify=tls, timeout=15, trust_env=False, headers=headers
    ) as http:

        async def measure(repeat, phase, concurrency):
            tick = perf_counter()
            status, correct, metrics = 0, False, {}
            try:
                response = await http.get("/api/v1/data/customers")
                status = response.status_code
                result = response.json()
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
            except httpx.HTTPError:
                pass
            rows.append(
                {
                    "repeat": repeat,
                    "phase": phase,
                    "concurrency": concurrency,
                    "http_ms": (perf_counter() - tick) * 1000,
                    "status": status,
                    "correct": int(correct),
                    "error": int(not correct),
                    **{
                        key: metrics.get(key, 0)
                        for key in ("opa_eval_ms", "database_ms", "gateway_ms")
                    },
                }
            )

        def summarize(repeat, phase, concurrency, tick, first):
            selected = rows[first:]
            elapsed = perf_counter() - tick
            latency = [row["http_ms"] for row in selected]
            groups.append(
                {
                    "repeat": repeat,
                    "phase": phase,
                    "concurrency": concurrency,
                    "samples": len(selected),
                    "elapsed_seconds": elapsed,
                    "p50_ms": percentile(latency, 0.5),
                    "p95_ms": percentile(latency, 0.95),
                    "errors": sum(row["error"] for row in selected),
                    "correct": sum(row["correct"] for row in selected),
                    "throughput_rps": len(selected) / elapsed,
                    "timing_valid": max(latency) < 30000
                    and (phase != "throughput" or elapsed < args.duration + 30),
                }
            )
            print(f"repeat {repeat}: {phase} c{concurrency}, {len(selected)} samples", flush=True)

        for repeat in range(1, args.repeats + 1):
            for _ in range(args.warmup):
                await measure(repeat, "warmup", 1)
            tick, first = perf_counter(), len(rows)
            for _ in range(args.samples):
                await measure(repeat, "latency", 1)
            summarize(repeat, "latency", 1, tick, first)
            for concurrency in args.concurrency:
                tick, first = perf_counter(), len(rows)
                deadline = tick + args.duration

                async def worker():
                    while perf_counter() < deadline:
                        await measure(repeat, "throughput", concurrency)

                await asyncio.gather(*(worker() for _ in range(concurrency)))
                summarize(repeat, "throughput", concurrency, tick, first)
    with (args.output / "raw.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (args.output / "summary.json").write_text(json.dumps(groups, indent=2))
    (args.output / "environment.json").write_text(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "samples": args.samples,
                "warmup": args.warmup,
                "duration": args.duration,
                "repeats": args.repeats,
                "concurrency": args.concurrency,
                "protocol": "Same authenticated analyst and enrolled TLS device; 12 PDP rules plus view plan; 3 DB source rows, 2 permitted, sensitive columns masked; elapsed includes drain. Pilot only.",
            },
            indent=2,
        )
    )
    if any(not group["timing_valid"] or group["errors"] for group in groups):
        raise RuntimeError(
            "Invalid run: raw evidence saved; do not report these timings as successful performance"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--duration", type=float, default=5)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 5, 10])
    parser.add_argument("--output", type=Path, default=ROOT / "benchmark/results/final-gateway")
    args = parser.parse_args()
    if (
        args.samples <= 0
        or args.warmup < 0
        or args.duration <= 0
        or args.repeats <= 0
        or any(c < 1 or c > 20 for c in args.concurrency)
    ):
        parser.error("Invalid or excessive measurement parameters")
    asyncio.run(run(args))
