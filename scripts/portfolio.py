"""Reproducible local bootstrap and offline two-person policy release workflow."""

import argparse
import base64
import json
import os
import re
import ssl
import urllib.request
import secrets
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.gateway.releases import (
    ReleaseRepository,
    atomic_json,
    digest,
    engine_revision,
    local_release,
    sign_release,
)
from app.gateway.security import hash_password
from scripts.setup_gateway import ROOT, setup

RUNTIME = ROOT / ".gateway"


def initialize(project=None):
    project = valid_project(project or os.getenv("GATEWAY_COMPOSE_PROJECT", "abac-portfolio"))
    setup(RUNTIME, [], "127.0.0.0/8,::1/128,172.16.0.0/12,192.168.0.0/16")
    # Private Docker/NAT ranges are allowed for this loopback-only local demo.
    # Real deployment must use explicit networks for its own ingress topology.
    registry = json.loads((RUNTIME / "server/registry.json").read_text())
    credentials = json.loads((RUNTIME / "credentials.json").read_text())
    for username, role in (("beta_analyst", "marketing_analyst"), ("beta_admin", "admin")):
        password = secrets.token_urlsafe(18)
        credentials[username] = password
        registry["accounts"][username] = {
            "subject": {
                "id": username,
                "tenant_id": "beta",
                "role": role,
                "department": "marketing",
                "clearance": "restricted" if role == "admin" else "confidential",
            },
            "password_hash": hash_password(password),
            "enabled": True,
            "auth_version": 1,
        }
    atomic_json(RUNTIME / "server/registry.json", registry)
    atomic_json(RUNTIME / "credentials.json", credentials)
    private_dir = RUNTIME / "maintainers"
    private_dir.mkdir()
    trust = {}
    keys = {}
    for name in ("author", "reviewer"):
        key = Ed25519PrivateKey.generate()
        keys[name] = key
        (private_dir / (name + ".pem")).write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        trust[name] = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    atomic_json(RUNTIME / "server/trusted-policy-keys.json", trust)
    policies = json.loads((RUNTIME / "server/policies.json").read_text())
    release = local_release(
        policies, "Portfolio baseline: tenant isolation and mandatory analyst masking"
    )
    for name, key in keys.items():
        sign_release(release, name, key)
    directory = RUNTIME / "server/releases"
    atomic_json(directory / (release["revision"] + ".json"), release)
    repository = ReleaseRepository(directory, RUNTIME / "server/trusted-policy-keys.json")
    repository.activate(release["revision"], None)
    atomic_json(
        RUNTIME / "server/deployment.json", {"deployment": {"engine_revision": engine_revision()}}
    )
    with (RUNTIME / "gateway.env").open("a", encoding="utf-8") as output:
        output.write("GATEWAY_AUDIT_KEY=" + secrets.token_hex(32) + "\n")
        output.write("GATEWAY_SESSION_DB_PASSWORD=" + secrets.token_hex(24) + "\n")
        output.write("GATEWAY_COMPOSE_PROJECT=" + project + "\n")
    (RUNTIME / "state").mkdir(exist_ok=True)
    if os.name != "nt":
        RUNTIME.chmod(0o700)
        for path in RUNTIME.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
            elif path.suffix in {".key", ".pem"} or path.name in {
                "gateway.env",
                "credentials.json",
                "registry.json",
            }:
                path.chmod(0o600)
        # This subtree is mounted as /runtime for UID10001. The outer .gateway
        # stays 0700 to protect it from unrelated host users; /runtime contains
        # signed policy data, public verification keys and hashed account records.
        server = RUNTIME / "server"
        server.chmod(0o755)
        for path in server.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)
    print("Initialized local portfolio runtime; credentials and signing keys remain in .gateway.")
    print("Initial revision:", release["revision"])


def valid_project(value):
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,62}", value):
        raise ValueError("Invalid Compose project name")
    return value


def compose_project():
    value = os.getenv("GATEWAY_COMPOSE_PROJECT")
    if value is None and (RUNTIME / "gateway.env").exists():
        for line in (RUNTIME / "gateway.env").read_text(encoding="utf-8").splitlines():
            key, separator, candidate = line.partition("=")
            if separator and key == "GATEWAY_COMPOSE_PROJECT":
                value = candidate
    return valid_project(value or "abac-portfolio")


def compose(*args, **kwargs):
    return subprocess.run(
        [
            "docker",
            "compose",
            "--project-name",
            compose_project(),
            "--env-file",
            str(RUNTIME / "gateway.env"),
            "-f",
            str(ROOT / "compose.gateway.yml"),
            *args,
        ],
        cwd=ROOT,
        check=True,
        **kwargs,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("up", "down", "status", "migrate"):
        sub.add_parser(name)
    init_parser = sub.add_parser("init")
    init_parser.add_argument(
        "--project", help="Isolated Compose project name; defaults to abac-portfolio"
    )
    doctor_parser = sub.add_parser("doctor")
    doctor_parser.add_argument(
        "--live", action="store_true", help="Also verify HTTPS readiness using the generated CA"
    )
    proposal = sub.add_parser("propose")
    proposal.add_argument("--policies", type=Path, default=RUNTIME / "server/policies.json")
    proposal.add_argument("--description", required=True)
    proposal.add_argument("--mask-admin", action="store_true")
    proposal.add_argument("--key", type=Path, required=True)
    proposal.add_argument("--signer", required=True)
    approval = sub.add_parser("approve")
    approval.add_argument("revision")
    approval.add_argument("--key", type=Path, required=True)
    approval.add_argument("--signer", required=True)
    activation = sub.add_parser("activate")
    activation.add_argument("revision")
    activation.add_argument("--expected", required=True)
    args = parser.parse_args()
    repository = ReleaseRepository(
        RUNTIME / "server/releases", RUNTIME / "server/trusted-policy-keys.json"
    )
    if args.command == "init":
        initialize(args.project)
    elif args.command == "up":
        compose("up", "-d", "--build", "--wait", "--wait-timeout", "180")
    elif args.command == "down":
        compose("down")  # Named volumes intentionally survive.
    elif args.command == "migrate":
        compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "gateway_owner",
            "-d",
            "gateway_db",
            "-f",
            "/docker-entrypoint-initdb.d/04-tenants.sql",
        )
        compose("exec", "-T", "postgres", "sh", "/docker-entrypoint-initdb.d/05-sessions.sh")
    elif args.command == "doctor":
        subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], check=True)
        if not (RUNTIME / "gateway.env").exists():
            raise SystemExit("Run python -m scripts.portfolio init first.")
        release = repository.active()
        print("Verified signatures and engine:", release["revision"])
        compose("config", "--quiet")
        print("Configuration validated.")
        if args.live:
            values = dict(
                line.split("=", 1)
                for line in (RUNTIME / "gateway.env").read_text().splitlines()
                if "=" in line and not line.startswith("#")
            )
            port = int(values.get("GATEWAY_PORT", "28443"))
            if not 1 <= port <= 65535:
                raise ValueError("Invalid Gateway port")
            context = ssl.create_default_context(cafile=str(RUNTIME / "tls/ca.crt"))
            request = urllib.request.Request(f"https://127.0.0.1:{port}/health")
            with urllib.request.urlopen(request, context=context, timeout=5) as response:
                health = json.load(response)
            if not all(
                health.get(key) is True
                for key in (
                    "opa_ready",
                    "database_ready",
                    "policy_ready",
                    "audit_ready",
                    "session_ready",
                    "access_ready",
                )
            ):
                raise ValueError("Live Gateway readiness failed")
            print("CA-verified HTTPS readiness: PASS")
        else:
            print("Use doctor --live after startup to verify actual readiness.")
    elif args.command == "status":
        compose("ps")
    elif args.command == "activate":
        repository.activate(args.revision, args.expected)
        print("Activated:", args.revision)
    else:
        key = serialization.load_pem_private_key(args.key.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Ed25519 key required")
        if args.command == "propose":
            release = local_release(json.loads(args.policies.read_text()), args.description)
            release["payload"]["view"]["mask_admin"] = args.mask_admin
            release["revision"] = digest(release["payload"])
        else:
            release = repository.read(args.revision, required=1)
        sign_release(release, args.signer, key)
        atomic_json(repository.directory / (release["revision"] + ".json"), release)
        print("Signed revision:", release["revision"])


if __name__ == "__main__":
    main()
