import json

import pytest
from cryptography.hazmat.primitives.serialization import pkcs12

from scripts.export_device import export
from scripts.setup_gateway import setup
from scripts.renew_gateway_server import renew


def test_setup_preserves_existing_secrets_and_exports_bound_device(tmp_path):
    runtime = tmp_path / "runtime"
    registry = setup(runtime, ["192.0.2.10"], "127.0.0.0/8", 8, 18)
    original = (runtime / "gateway.env").read_bytes()
    with pytest.raises(ValueError):
        setup(runtime, [], "127.0.0.0/8")
    assert (runtime / "gateway.env").read_bytes() == original
    policies = json.loads((runtime / "server/policies.json").read_text(encoding="utf-8"))
    assert next(p for p in policies if p["id"] == "P10")["conditions"][0]["value"] == 8
    path = export(runtime)
    password = json.loads((runtime / "device-import.json").read_text())["password"].encode()
    key, certificate, chain = pkcs12.load_key_and_certificates(path.read_bytes(), password)
    assert key is not None and len(chain) == 1
    assert format(certificate.serial_number, "X") in registry["devices"]
    registry_bytes = (runtime / "server/registry.json").read_bytes()
    renewed = renew(runtime, ["192.0.2.11"])
    assert renewed.issuer == certificate.issuer
    assert (runtime / "server/registry.json").read_bytes() == registry_bytes
    with pytest.raises(ValueError):
        export(runtime)


@pytest.mark.parametrize("hours", [(18, 8), (-1, 18), (8, 25)])
def test_invalid_business_hours_create_no_runtime(tmp_path, hours):
    with pytest.raises(ValueError):
        setup(tmp_path / "invalid", [], "127.0.0.0/8", *hours)
    assert not (tmp_path / "invalid").exists()
