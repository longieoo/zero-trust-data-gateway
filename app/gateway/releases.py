"""Content-addressed, two-person signed policy releases; no private key in Gateway.

This is an application release protocol, NOT OPA's native tar bundle protocol.
Only data changes hot-reload; interpreter changes require deployment and reapproval.
"""

import base64
import hashlib
import json
import os
import re
import time
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.jsonio import strict_json_loads
from app.policy_repository import validate_policies

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VIEW = {"mask_admin": False, "limit": 100}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def engine_revision():
    # Replay is invalidated by changes to semantics or strict envelope validation.
    paths = [
        "policies/engine.rego",
        "policies/gateway.rego",
        "app/decision/__init__.py",
        "app/gateway/evaluator.py",
        "app/gateway/database.py",
        "app/opa_client/__init__.py",
    ]
    return digest({name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in paths})


def validate_payload(payload):
    if set(payload) != {"schema", "engine_revision", "policies", "view", "description"}:
        raise ValueError("Invalid release fields")
    if type(payload["schema"]) is not int or payload["schema"] != 1:
        raise ValueError("Unsupported release schema")
    if payload["engine_revision"] != engine_revision():
        raise ValueError("Release interpreter differs from deployed interpreter")
    if not isinstance(payload["description"], str) or not 1 <= len(payload["description"]) <= 500:
        raise ValueError("Release description required")
    validate_policies(payload["policies"])
    if not 1 <= len(payload["policies"]) <= 5000:
        raise ValueError("Policy capacity exceeded")
    view = payload["view"]
    if set(view) != {"mask_admin", "limit"} or type(view["mask_admin"]) is not bool:
        raise ValueError("Invalid view profile")
    if type(view["limit"]) is not int or not 1 <= view["limit"] <= 100:
        raise ValueError("Invalid row limit")


def local_release(policies, description="Unsigned development fixture"):
    payload = {
        "schema": 1,
        "engine_revision": engine_revision(),
        "policies": policies,
        "view": dict(DEFAULT_VIEW),
        "description": description,
    }
    validate_payload(payload)
    return {"revision": digest(payload), "payload": payload, "signatures": {}}


def sign_release(release, key_id, private_key):
    validate_payload(release["payload"])
    if release["revision"] != digest(release["payload"]):
        raise ValueError("Revision mismatch")
    release["signatures"][key_id] = base64.b64encode(
        private_key.sign(canonical(release["payload"]))
    ).decode()
    return release


def verify_release(release, trusted_keys, required=2):
    if set(release) != {"revision", "payload", "signatures"}:
        raise ValueError("Invalid release envelope")
    validate_payload(release["payload"])
    if release["revision"] != digest(release["payload"]):
        raise ValueError("Revision mismatch")
    # Count distinct public keys, not names: aliasing a key must not permit self-approval.
    verified = set()
    for key_id, signature in release["signatures"].items():
        public = base64.b64decode(trusted_keys[key_id], validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(
            base64.b64decode(signature, validate=True), canonical(release["payload"])
        )
        verified.add(public)
    if len(verified) < required:
        raise ValueError("Two independent authorized signatures required")
    return release


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(canonical(data))
            handle.flush()
            os.fsync(handle.fileno())
        # Windows bind-mount readers/AV may briefly deny rename sharing. Retry
        # the same atomic replacement; never fall back to truncate/write.
        for attempt in range(20):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if os.name != "nt" or attempt == 19:
                    raise
                time.sleep(0.05)
    finally:
        temporary.unlink(missing_ok=True)


class ReleaseRepository:
    def __init__(self, directory, trust_file):
        self.directory = Path(directory)
        self.trust_file = Path(trust_file)

    def read(self, revision, required=2):
        if not re.fullmatch(r"[0-9a-f]{64}", revision):
            raise ValueError("Invalid revision")
        path = self.directory / (revision + ".json")
        if path.stat().st_size > 8_000_000:
            raise ValueError("Oversized policy release")
        release = strict_json_loads(path.read_text(encoding="utf-8"))
        if release["revision"] != revision:
            raise ValueError("Release path mismatch")
        trust = strict_json_loads(self.trust_file.read_text(encoding="utf-8"))
        return verify_release(release, trust, required)

    def active(self):
        pointer = strict_json_loads((self.directory / "active.json").read_text(encoding="utf-8"))
        return self.read(pointer["revision"])

    def activate(self, revision, expected):
        """Single-controller compare-and-swap; rollback uses exactly the same checks."""
        lock = self.directory / ".activation.lock"
        handle = lock.open("x")
        try:
            pointer = self.directory / "active.json"
            previous = (
                strict_json_loads(pointer.read_text())["revision"] if pointer.exists() else None
            )
            if previous != expected:
                raise ValueError("Active revision changed; refresh before activation")
            self.read(revision)
            atomic_json(pointer, {"revision": revision, "previous": previous})
        finally:
            handle.close()
            lock.unlink()
