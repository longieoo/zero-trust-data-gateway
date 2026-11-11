"""Reissue only the server certificate with LAN SANs, preserving CA and device registry."""

import argparse
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]


def renew(runtime, hosts):
    tls = runtime / "tls"
    ca = x509.load_pem_x509_certificate((tls / "ca.crt").read_bytes())
    ca_key = serialization.load_pem_private_key((tls / "ca.key").read_bytes(), None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names = [x509.DNSName("localhost")]
    for host in {"127.0.0.1", "::1", *hosts}:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ABAC Gateway")]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    # Preserve the previous pair for local recovery; runtime is excluded from delivery.
    for suffix in ("crt", "key"):
        path = tls / f"server.{suffix}"
        (tls / f"server.previous.{suffix}").write_bytes(path.read_bytes())
    (tls / "server.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (tls / "server.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return certificate


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts", nargs="+", required=True)
    args = parser.parse_args()
    renew(ROOT / ".gateway", args.hosts)
    print(
        "Server certificate renewed. Restart only proxy to load it; existing accounts/devices remain valid."
    )
