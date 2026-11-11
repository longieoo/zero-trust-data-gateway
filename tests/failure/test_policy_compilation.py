import os
import shutil
import subprocess


def test_invalid_rego_rejected_by_real_opa(tmp_path):
    policy = tmp_path / "invalid.rego"
    policy.write_text("package invalid\nallow if { this is not valid rego !!! }\n")
    binary = os.getenv("OPA_BIN") or shutil.which("opa")
    result = subprocess.run([binary, "check", str(policy)], capture_output=True, text=True)
    assert result.returncode != 0
    assert "rego_parse_error" in result.stderr or "rego_parse_error" in result.stdout
