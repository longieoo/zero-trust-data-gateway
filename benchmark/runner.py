"""Benchmark live FastAPI -> OPA with raw per-request measurements.

Default full protocol: 100 warmups, 1000 sequential samples, 60 seconds per
concurrency, three repetitions, trace on and off. --quick is explicitly a pilot.
"""

import argparse
import asyncio
import csv
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import httpx

from benchmark.generate_policies import generate
from benchmark.oracle import decide

ROOT = Path(__file__).resolve().parents[1]
FIELDS = [
    "count",
    "trace",
    "repeat",
    "phase",
    "concurrency",
    "sample",
    "latency_ms",
    "opa_eval_ms",
    "opa_roundtrip_ms",
    "candidate_count",
    "matched_count",
    "expected",
    "actual",
    "correct",
    "error",
    "timeout",
]


def workload(policies, data_root=None, balanced=False):
    data_root = data_root or ROOT / "data"
    users = {
        r["attributes"]["id"]: r["attributes"]
        for r in json.loads((data_root / "users.json").read_text())
    }
    resources = {
        r["attributes"]["id"]: r["attributes"]
        for r in json.loads((data_root / "resources.json").read_text())
    }
    corpus = []
    for resource in ("production_db", "risk_dataset", "public_report"):
        for risk in (20, 69, 70, 90):
            context = {
                "device_trusted": True,
                "location": "office",
                "time": "2026-01-15T10:00:00Z",
                "risk_score": risk,
            }
            payload = {
                "subject_id": "engineer",
                "resource_id": resource,
                "action": "read",
                "context": context,
                "baseline": "context_abac",
                "strategy": "deny-overrides",
            }
            attributes = {
                "subject": users["engineer"],
                "resource": resources[resource],
                "context": {**context, "hour": 10},
                "action": "read",
            }
            corpus.append((payload, decide(attributes, policies)))
    if balanced:
        # At 5,000 rules the legacy corpus is all DENY. Add known-Permit control requests.
        for index in range(12):
            payload = {**corpus[index][0], "resource_id": "benchmark_control"}
            payload["context"] = {**payload["context"], "risk_score": (0, 20, 69)[index % 3]}
            attributes = {
                "subject": users["engineer"],
                "resource": resources["benchmark_control"],
                "context": {**payload["context"], "hour": 10},
                "action": "read",
            }
            corpus.append((payload, decide(attributes, policies)))
    return corpus


async def run_level(args, count, repetition, directory):
    instance_id = str(uuid4())
    policies = generate(count)
    policy_path = directory / f"policies-{count}.json"
    policy_path.write_text(json.dumps(policies), encoding="utf-8")
    corpus = workload(policies, directory / "data", args.workload == "balanced")
    (directory / f"expected-{count}.json").write_text(
        json.dumps(corpus, indent=2), encoding="utf-8"
    )
    env = {
        **os.environ,
        "POLICY_FILE": str(policy_path.resolve()),
        "SIMULATION_MODE": "1",
        "DEV_FAILURES": "0",
        "OPA_TIMEOUT": str(args.timeout),
        "ATTRIBUTE_DIR": str((directory / "data").resolve()),
        "BENCHMARK_INSTANCE": instance_id,
    }
    log = (directory / f"api-{count}-{repetition}.log").open("w")
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.api:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(args.port),
            "--no-access-log",
        ],
        cwd=ROOT,
        env=env,
        stdout=log,
        stderr=log,
    )
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{args.port}",
            timeout=args.timeout + 5,
            trust_env=False,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=60),
        ) as client:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("Benchmark API exited; inspect its log for port conflicts")
                try:
                    health = await client.get("/health")
                    if (
                        health.status_code == 200
                        and health.json().get("opa_ready")
                        and health.json().get("benchmark_instance") == instance_id
                    ):
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.1)
            else:
                raise RuntimeError("Benchmark API failed to start")
            for trace_value in args.traces:
                trace = bool(trace_value)
                raw_path = directory / f"raw-{count}-{int(trace)}-{repetition}.csv"
                with raw_path.open("w", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=FIELDS)
                    writer.writeheader()
                    sequence = 0

                    async def request(phase, concurrency):
                        nonlocal sequence
                        index = sequence
                        sequence += 1
                        payload, expected = corpus[index % len(corpus)]
                        tick = time.perf_counter()
                        row = dict.fromkeys(FIELDS, 0)
                        row.update(
                            count=count,
                            trace=int(trace),
                            repeat=repetition,
                            phase=phase,
                            concurrency=concurrency,
                            sample=index,
                            expected=expected,
                            actual="ERROR",
                        )
                        try:
                            response = await client.post(
                                "/evaluate", json={**payload, "trace": trace}
                            )
                            row["latency_ms"] = (time.perf_counter() - tick) * 1000
                            response.raise_for_status()
                            result = response.json()
                            row["actual"] = result["decision"]
                            row["error"] = int(
                                result["decision_status"] == "DENIED_DUE_TO_TECHNICAL_FAILURE"
                            )
                            row["timeout"] = int(result["reason_code"] == "OPA_TIMEOUT")
                            row["correct"] = int(row["actual"] == expected and not row["error"])
                            for field in (
                                "opa_eval_ms",
                                "opa_roundtrip_ms",
                                "candidate_count",
                                "matched_count",
                            ):
                                row[field] = result["metrics"][field]
                        except (httpx.HTTPError, ValueError, KeyError) as exc:
                            row["latency_ms"] = (time.perf_counter() - tick) * 1000
                            row["error"] = 1
                            row["timeout"] = int(isinstance(exc, httpx.TimeoutException))
                        writer.writerow(row)

                    for _ in range(args.warmup):
                        await request("warmup", 1)
                    print(
                        f"count={count} trace={trace} repeat={repetition}: warmup complete",
                        flush=True,
                    )
                    phases = []
                    if not args.skip_latency:
                        start = time.perf_counter()
                        for _ in range(args.samples):
                            await request("latency", 1)
                        phases.append(
                            {
                                "phase": "latency",
                                "concurrency": 1,
                                "seconds": time.perf_counter() - start,
                            }
                        )
                    handle.flush()
                    if not args.skip_latency:
                        print(
                            f"count={count} trace={trace}: {args.samples} latency samples complete",
                            flush=True,
                        )
                    timing_path = directory / f"timing-{count}-{int(trace)}-{repetition}.json"
                    timing_path.write_text(json.dumps(phases, indent=2))
                    for concurrency in [] if args.skip_throughput else args.concurrency:
                        start = time.perf_counter()
                        deadline = start + args.duration

                        async def worker():
                            while time.perf_counter() < deadline:
                                await request("throughput", concurrency)

                        await asyncio.gather(*(worker() for _ in range(concurrency)))
                        phases.append(
                            {
                                "phase": "throughput",
                                "concurrency": concurrency,
                                "seconds": time.perf_counter() - start,
                            }
                        )
                        handle.flush()
                        timing_path.write_text(json.dumps(phases, indent=2))
                        print(
                            f"count={count} trace={trace} concurrency={concurrency}: throughput complete",
                            flush=True,
                        )
                    (directory / f"timing-{count}-{int(trace)}-{repetition}.json").write_text(
                        json.dumps(phases, indent=2)
                    )
    finally:
        server.terminate()
        server.wait(timeout=20)
        log.close()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--counts", nargs="+", type=int, default=[10, 100, 500, 1000, 5000])
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--concurrency", nargs="+", type=int, default=[1, 10, 50])
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--port", type=int, default=18000)
    parser.add_argument("--output", type=Path, default=ROOT / "benchmark/results/full")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--workload", choices=["balanced", "legacy"], default="balanced")
    parser.add_argument(
        "--skip-latency",
        action="store_true",
        help="Rerun throughput phases only after fresh warmup",
    )
    parser.add_argument("--traces", nargs="+", type=int, choices=[0, 1], default=[0, 1])
    parser.add_argument("--skip-throughput", action="store_true", help="Run latency sampling only")
    args = parser.parse_args()
    if args.quick:
        args.samples, args.warmup, args.duration, args.repeats = 30, 10, 2, 1
    if (
        any(count < 2 for count in args.counts)
        or args.samples < 1
        or args.warmup < 0
        or args.duration <= 0
        or args.repeats < 1
        or args.timeout <= 0
        or any(value < 1 for value in args.concurrency)
    ):
        parser.error(
            "Counts must be >=2; samples, duration, repeats, timeout and concurrency positive"
        )
    if len(set(args.counts)) != len(args.counts) or len(set(args.traces)) != len(args.traces):
        parser.error("Duplicate counts or traces would overwrite measurements")
    args.output.mkdir(parents=True, exist_ok=False)
    shutil.copytree(ROOT / "data", args.output / "data")
    now = datetime.now(timezone.utc).isoformat()
    for name in ("users", "resources", "contexts"):
        path = args.output / "data" / f"{name}.json"
        rows = json.loads(path.read_text())
        if name == "resources" and args.workload == "balanced":
            rows.append(
                {
                    "attributes": {
                        "id": "benchmark_control",
                        "type": "report",
                        "department": "data",
                        "sensitivity": "public",
                    },
                    "source": "synthetic-benchmark-control",
                    "timestamp": now,
                    "ttl_seconds": 86400,
                }
            )
        for row in rows.values() if isinstance(rows, dict) else rows:
            row["timestamp"] = now
        path.write_text(json.dumps(rows, indent=2))
    config = {
        **vars(args),
        "output": str(args.output),
        "platform": platform.platform(),
        "python": sys.version,
        "cpu_count": os.cpu_count(),
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "policy_engine_sha256": hashlib.sha256(
            (ROOT / "policies/engine.rego").read_bytes()
        ).hexdigest(),
        "protocol": "pilot" if args.quick else "configured",
        "trace_off_semantics": "Compact OPA transport; all outcomes and condition booleans validated.",
        "application_version": "2.0.0",
        "catalogue_cache": os.getenv("OPA_CATALOGUE_CACHE", "1"),
    }
    (args.output / "environment.json").write_text(json.dumps(config, indent=2))
    for repetition in range(1, args.repeats + 1):
        for count in args.counts:
            await run_level(args, count, repetition, args.output)


if __name__ == "__main__":
    asyncio.run(main())
