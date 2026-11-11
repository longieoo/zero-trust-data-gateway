"""Export existing demo client key to a password-protected browser import file."""

import json
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

ROOT = Path(__file__).resolve().parents[1]


def export(runtime):
    destination = runtime / "company-device.p12"
    if destination.exists():
        raise ValueError("Device import already exists; credentials are preserved")
    key = serialization.load_pem_private_key(
        (runtime / "tls/company-device.key").read_bytes(), None
    )
    certificate = x509.load_pem_x509_certificate((runtime / "tls/company-device.crt").read_bytes())
    ca = x509.load_pem_x509_certificate((runtime / "tls/ca.crt").read_bytes())
    password = secrets.token_urlsafe(20)
    destination.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"ABAC company device",
            key,
            certificate,
            [ca],
            serialization.BestAvailableEncryption(password.encode()),
        )
    )
    (runtime / "device-import.json").write_text(
        json.dumps(
            {"password": password, "certificate_serial": format(certificate.serial_number, "X")},
            indent=2,
        ),
        encoding="utf-8",
    )
    return destination


if __name__ == "__main__":
    print(
        f"Created {export(ROOT / '.gateway')}; import password stays in .gateway/device-import.json"
    )
