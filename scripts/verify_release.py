"""One sequential final gate binding all verification to one code/config fingerprint."""

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

from scripts.portfolio import ROOT


def fingerprint():
    files = {}
    for directory in ("app", "policies", "scripts", "ui", "tests", "data", "benchmark", ".github"):
        for path in (ROOT / directory).rglob("*"):
            if (
                path.is_file()
                and path.suffix
                in {
                    ".py",
                    ".rego",
                    ".json",
                    ".js",
                    ".cjs",
                    ".css",
                    ".html",
                    ".sql",
                    ".sh",
                    ".yml",
                    ".yaml",
                    ".ps1",
                }
                and "__pycache__" not in path.parts
                and path.name != "results.json"
            ):
                files[path.relative_to(ROOT).as_posix()] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
    for path in (
        list(ROOT.glob("requirements*.txt"))
        + list(ROOT.glob("Dockerfile*"))
        + list(ROOT.glob("compose*.yml"))
        + [ROOT / "pyproject.toml", ROOT / ".dockerignore"]
    ):
        files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(), files


def main():
    output = ROOT / "evidence"
    output.mkdir(exist_ok=True)
    before, files = fingerprint()
    python = sys.executable
    steps = [
        ("lint", [python, "-m", "ruff", "check", "app", "tests", "scripts"]),
        ("pytest", [python, "-m", "pytest", "-q", "--junitxml=evidence/pytest.xml"]),
        ("ui-unit", ["node", "tests/ui/gateway_session.cjs"]),
        ("compose", [python, "-m", "scripts.portfolio", "up"]),
        ("live", [python, "-m", "scripts.validate_portfolio"]),
        ("browser", ["node", "tests/ui/portfolio_live.cjs"]),
        ("benchmark", [python, "-m", "scripts.benchmark_portfolio"]),
        (
            "dependency-audit",
            [
                python,
                "-m",
                "pip_audit",
                "--no-deps",
                "--disable-pip",
                "-r",
                "requirements-lock.txt",
                "-f",
                "json",
                "-o",
                "evidence/dependency-audit.json",
            ],
        ),
    ]
    records = []
    success = False
    try:
        for name, command in steps:
            print("RUN " + name, flush=True)
            started = time.perf_counter()
            with (output / (name + ".log")).open("w", encoding="utf-8") as log:
                result = subprocess.run(
                    command, cwd=ROOT, env=os.environ.copy(), stdout=log, stderr=subprocess.STDOUT
                )
            records.append(
                {
                    "step": name,
                    "returncode": result.returncode,
                    "elapsed_seconds": time.perf_counter() - started,
                    "log": name + ".log",
                }
            )
            if result.returncode:
                raise RuntimeError(f"{name} failed; inspect evidence/{name}.log")
            print("PASS " + name, flush=True)
        success = True
    finally:
        after, _ = fingerprint()
        receipt = {
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "source_sha256": before,
            "source_unchanged": after == before,
            "passed": success and after == before,
            "steps": records,
            "files": files,
        }
        (output / "verification-receipt.json").write_text(
            json.dumps(receipt, indent=2), encoding="utf-8"
        )
    if after != before:
        raise RuntimeError("Code changed during verification; receipt is invalid")
    print("Verified current code state:", before)


if __name__ == "__main__":
    main()
