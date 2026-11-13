"""Create local demo secrets and a private CA. Existing state is never overwritten."""

import argparse
import ipaddress
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.gateway.security import hash_password
from app.jsonio import strict_json_loads

ROOT = Path(__file__).resolve().parents[1]


def setup(directory, hosts, office_networks, start_hour=0, end_hour=24):
    if directory.exists():
        raise ValueError(
            "Runtime already exists; preserve credentials and certificates. Use a new directory for a new deployment."
        )
    if not 0 <= start_hour < end_hour <= 24:
        raise ValueError("Invalid business hours")
    for network in office_networks.split(","):
        ipaddress.ip_network(network.strip())
    tls = directory / "tls"
    tls.mkdir(parents=True)
    runtime = directory / "server"
    runtime.mkdir()
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ABAC Local Demo CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )

    def write_pair(label, key, cert):
        (tls / f"{label}.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (tls / f"{label}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    write_pair("ca", ca_key, ca)

    def leaf(label, purpose, sans=None):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(cert_name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([purpose]), critical=False)
            .add_extension(
                x509.KeyUsage(True, False, True, False, False, False, False, False, False),
                critical=True,
            )
        )
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        write_pair(label, key, cert)
        return cert

    sans = [x509.DNSName("localhost")]
    for host in {"127.0.0.1", "::1", *hosts}:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            sans.append(x509.DNSName(host))
    leaf("server", ExtendedKeyUsageOID.SERVER_AUTH, sans)
    client = leaf("company-device", ExtendedKeyUsageOID.CLIENT_AUTH)
    # Issued by our CA but intentionally not enrolled: negative TLS/registry test.
    leaf("unregistered-device", ExtendedKeyUsageOID.CLIENT_AUTH)
    accounts = {
        "engineer": ("data_engineer", "data", "restricted"),
        "analyst": ("marketing_analyst", "marketing", "confidential"),
        "finance": ("risk_analyst", "finance", "restricted"),
        "admin": ("admin", "data", "restricted"),
        "data_owner": ("admin", "data", "restricted"),
    }
    credentials, rows = {}, {}
    for username, (role, department, clearance) in accounts.items():
        password = secrets.token_urlsafe(18)
        credentials[username] = password
        rows[username] = {
            "subject": {
                "id": username,
                "tenant_id": "demo",
                "role": role,
                "department": department,
                "clearance": clearance,
            },
            "password_hash": hash_password(password),
            "enabled": True,
            "auth_version": 1,
        }
    registry = {
        "accounts": rows,
        "devices": {
            format(client.serial_number, "X"): {"id": "company-laptop-01", "enabled": True}
        },
    }
    (runtime / "registry.json").write_text(json.dumps(registry, indent=2), encoding="utf-8")
    (directory / "credentials.json").write_text(json.dumps(credentials, indent=2), encoding="utf-8")
    policies = strict_json_loads((ROOT / "policies/policies.json").read_text(encoding="utf-8"))
    for policy in policies:
        if policy["id"] in {"P10", "P11"}:
            boundary = start_hour if policy["id"] == "P10" else end_hour
            policy["conditions"][0]["value"] = boundary
            policy["version"] = "3.0.0"
            policy["description"] = policy["rationale"] = (
                f"Gateway business hours {start_hour:02d}:00–{end_hour:02d}:00 Asia/Bangkok."
            )
    (runtime / "policies.json").write_text(json.dumps(policies, indent=2), encoding="utf-8")
    proxy_secret = secrets.token_hex(32)
    env = {
        "POSTGRES_PASSWORD": secrets.token_hex(24),
        "GATEWAY_DB_PASSWORD": secrets.token_hex(24),
        "GATEWAY_JWT_SECRET": secrets.token_hex(32),
        "GATEWAY_PROXY_SECRET": proxy_secret,
        "OFFICE_NETWORKS": office_networks,
    }
    (directory / "gateway.env").write_text(
        "\n".join(f"{key}={value}" for key, value in env.items()) + "\n", encoding="utf-8"
    )
    (directory / "nginx.conf").write_text(
        """events {}
http {
  limit_req_zone $binary_remote_addr zone=login:1m rate=5r/m;
  server {
    listen 443 ssl;
    server_name _;
    ssl_certificate /etc/gateway/tls/server.crt;
    ssl_certificate_key /etc/gateway/tls/server.key;
    ssl_client_certificate /etc/gateway/tls/ca.crt;
    ssl_verify_client optional;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 8k;
    add_header Strict-Transport-Security "max-age=86400" always;
    location = /auth/login {
      limit_req zone=login burst=10 nodelay;
      include /etc/gateway/tls/proxy-headers.conf;
      proxy_pass http://gateway:8000;
    }
    location / {
      include /etc/gateway/tls/proxy-headers.conf;
      proxy_pass http://gateway:8000;
    }
  }
}
""",
        encoding="utf-8",
    )
    (tls / "proxy-headers.conf").write_text(
        f'''proxy_set_header X-Gateway-Proxy-Secret "{proxy_secret}";
proxy_set_header X-Gateway-Client-IP $remote_addr;
proxy_set_header X-Gateway-Device-Verified $ssl_client_verify;
proxy_set_header X-Gateway-Device-Serial $ssl_client_serial;
proxy_set_header X-Forwarded-For "";
proxy_set_header Host $host;
proxy_connect_timeout 3s;
proxy_read_timeout 10s;
''',
        encoding="utf-8",
    )
    (directory / "setup-metadata.json").write_text(
        json.dumps(
            {
                "created_at": now.isoformat(),
                "hosts": hosts,
                "office_networks": office_networks,
                "business_hours": [start_hour, end_hour],
                "timezone": "Asia/Bangkok",
                "note": "Generated synthetic credentials/data; demo heuristic risk.",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return registry


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts", nargs="*", default=[])
    parser.add_argument("--office-networks", default="127.0.0.0/8,::1/128")
    parser.add_argument("--start-hour", type=int, default=0)
    parser.add_argument("--end-hour", type=int, default=24)
    args = parser.parse_args()
    setup(ROOT / ".gateway", args.hosts, args.office_networks, args.start_hour, args.end_hour)
    print(
        "Created .gateway runtime. Secrets/private keys stay local and are excluded from delivery."
    )
    print(
        f"Business hours: {args.start_hour:02d}:00–{args.end_hour:02d}:00 Asia/Bangkok. See .gateway/credentials.json locally."
    )
