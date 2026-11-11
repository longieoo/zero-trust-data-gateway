"""Deterministic varied policies with a deliberately sparse target distribution."""

import argparse
import json
import random
from pathlib import Path

from scripts.build_policies import condition


def generate(count: int, seed: int = 20260928) -> list:
    if count < 2:
        raise ValueError("At least two anchor policies required")
    rng = random.Random(seed)
    policies = []

    def add(index, target, conditions, effect, priority):
        policies.append(
            {
                "id": f"B{index:05}",
                "description": f"Synthetic benchmark rule {index}: {effect}.",
                "target": target,
                "conditions": conditions,
                "effect": effect,
                "priority": priority,
                "version": "bench-1.0.0",
                "reason_code": f"BENCH_{index}",
                "baselines": ["context_abac"],
                "rationale": "Controlled varied target/condition workload.",
            }
        )

    add(0, [], [condition("action", "eq", "read")], "Permit", 10)
    add(1, [], [condition("context.risk_score", "gte", 70)], "Deny", 100)
    for index in range(2, count):
        # 1 in 10 rules targets a real resource; others model a larger resource catalogue.
        resource = (
            rng.choice(["production_db", "risk_dataset", "public_report"])
            if index % 10 == 0
            else f"synthetic_resource_{rng.randrange(count)}"
        )
        target = [
            condition("resource.id", "eq", resource),
            condition("action", "eq", rng.choice(["read", "write", "delete"])),
        ]
        conditions = [
            condition("context.risk_score", rng.choice(["gte", "lt"]), rng.randrange(20, 100)),
            condition("context.location", "eq", rng.choice(["office", "vpn", "external"])),
        ]
        add(index, target, conditions, rng.choice(["Permit", "Deny"]), rng.randrange(1, 201))
    return policies


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(generate(args.count), indent=2), encoding="utf-8")
