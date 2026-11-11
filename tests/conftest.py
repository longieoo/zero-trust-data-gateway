import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone

import httpx
import pytest

from app.services import ROOT, DecisionService


@pytest.fixture(scope="session", autouse=True)
def real_opa():
    """Start an isolated real OPA; absence is a test failure, never a silent skip."""
    binary = os.getenv("OPA_BIN") or shutil.which("opa")
    if not binary:
        pytest.fail("Set OPA_BIN to OPA 1.4.2 executable or put opa on PATH")
    process = subprocess.Popen(
        [
            binary,
            "run",
            "--server",
            "--addr=127.0.0.1:18181",
            "--log-level=error",
            str(ROOT / "policies/engine.rego"),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                if (
                    httpx.get(
                        "http://127.0.0.1:18181/health", timeout=0.2, trust_env=False
                    ).status_code
                    == 200
                ):
                    break
            except httpx.HTTPError:
                time.sleep(0.05)
        else:
            pytest.fail("Real OPA failed to start on port 18181")
        yield
    finally:
        process.terminate()
        process.wait(timeout=10)


@pytest.fixture
def service(tmp_path, monkeypatch):
    shutil.copytree(ROOT / "data", tmp_path / "data")
    shutil.copytree(ROOT / "policies", tmp_path / "policies")
    now = datetime.now(timezone.utc).isoformat()
    for name in ("users", "resources", "contexts"):
        path = tmp_path / "data" / f"{name}.json"
        data = json.loads(path.read_text())
        for row in data.values() if isinstance(data, dict) else data:
            row["timestamp"] = now
        path.write_text(json.dumps(data))
    monkeypatch.setenv("OPA_URL", "http://127.0.0.1:18181")
    monkeypatch.setenv("SIMULATION_MODE", "1")
    monkeypatch.setenv("DEV_FAILURES", "1")
    monkeypatch.delenv("POLICY_FILE", raising=False)
    instance = DecisionService(tmp_path)
    yield instance
    instance.opa.client.close()
