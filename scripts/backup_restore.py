"""Encrypted local backups and non-destructive, isolated restore verification.

Backups contain credentials and private keys. They stay under .gateway/backups;
keep the separate backup key offline. Restore never targets running volumes.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import secrets
import sqlite3
import stat
import subprocess
import tempfile
import time
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"ZTBACKUP1"
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
RECONCILIATION_SQL = """SELECT json_build_object(
 'customers',(SELECT count(*) FROM customer_data),
 'financial',(SELECT count(*) FROM financial_records),
 'production',(SELECT count(*) FROM production_logs),
 'customer_fingerprint',(SELECT md5(coalesce(string_agg(row_to_json(t)::text,'' ORDER BY id),'')) FROM customer_data t),
 'financial_fingerprint',(SELECT md5(coalesce(string_agg(row_to_json(t)::text,'' ORDER BY id),'')) FROM financial_records t),
 'production_fingerprint',(SELECT md5(coalesce(string_agg(row_to_json(t)::text,'' ORDER BY id),'')) FROM production_logs t),
 'session_rows',(SELECT count(*) FROM gateway_auth.sessions),
 'session_fingerprint',(SELECT md5(coalesce(string_agg(row_to_json(t)::text,'' ORDER BY id),'')) FROM gateway_auth.sessions t),
 'force_rls_tables',(SELECT count(*) FROM pg_class WHERE relname IN ('customer_data','financial_records','production_logs') AND relforcerowsecurity),
 'rls_enabled_tables',(SELECT count(*) FROM pg_class WHERE relname IN ('customer_data','financial_records','production_logs') AND relrowsecurity),
 'tenant_policy_count',(SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relname IN ('customer_data','financial_records','production_logs') AND p.polname='gateway_tenant' AND NOT p.polpermissive),
 'scope_policy_count',(SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relname IN ('customer_data','financial_records','production_logs') AND p.polname='gateway_scope' AND p.polpermissive),
 'reader_role_safe',(SELECT NOT (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole) FROM pg_roles WHERE rolname='gateway_reader'),
 'reader_privileges',(SELECT json_agg(json_build_object('table',t,'select',has_table_privilege('gateway_reader',t,'SELECT'),'insert',has_table_privilege('gateway_reader',t,'INSERT'),'update',has_table_privilege('gateway_reader',t,'UPDATE'),'delete',has_table_privilege('gateway_reader',t,'DELETE')) ORDER BY t) FROM unnest(ARRAY['customer_data','financial_records','production_logs']) t),
 'session_role_permissions',json_build_object('select',has_table_privilege('gateway_session','gateway_auth.sessions','SELECT'),'insert',has_table_privilege('gateway_session','gateway_auth.sessions','INSERT'),'delete',has_table_privilege('gateway_session','gateway_auth.sessions','DELETE'),'update',has_table_privilege('gateway_session','gateway_auth.sessions','UPDATE')));"""


def sqlite_reconciliation(state, environment_file):
    """Read copied SQLite/WAL state and authenticate every encrypted replay snapshot.

    Only counts and digests leave this function. It never emits snapshot plaintext,
    passwords, account records or the audit encryption key.
    """
    from app.gateway.releases import canonical

    values = dict(
        line.split("=", 1)
        for line in Path(environment_file).read_text().splitlines()
        if "=" in line and not line.startswith("#")
    )
    cipher = AESGCM(bytes.fromhex(values["GATEWAY_AUDIT_KEY"]))
    result = {}
    for path in sorted(Path(state).resolve().glob("*.sqlite")):
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as database:
            database.row_factory = sqlite3.Row
            if database.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Restored SQLite integrity check failed")
            tables = {}
            snapshots = hashlib.sha256()
            snapshot_count = 0
            names = database.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            for entry in names:
                table = entry[0]
                quoted = '"' + table.replace('"', '""') + '"'
                rows = database.execute(f"SELECT * FROM {quoted} ORDER BY rowid").fetchall()
                row_hash = hashlib.sha256()
                for row in rows:
                    value = {
                        key: {"bytes": item.hex()} if isinstance(item, bytes) else item
                        for key, item in dict(row).items()
                    }
                    row_hash.update(canonical(value) + b"\n")
                    if table == "audit" and row["snapshot"] is not None:
                        raw = base64.b64decode(row["snapshot"], validate=True)
                        aad = canonical(
                            [
                                row["request_id"],
                                row["phase"],
                                row["tenant"],
                                row["actor"],
                                json.loads(row["metadata"]),
                            ]
                        )
                        plaintext = cipher.decrypt(raw[:12], raw[12:], aad)
                        snapshots.update(canonical(json.loads(plaintext)) + b"\n")
                        snapshot_count += 1
                tables[table] = {"rows": len(rows), "sha256": row_hash.hexdigest()}
            result[path.name] = {
                "tables": tables,
                "authenticated_snapshots": snapshot_count,
                "snapshot_sha256": snapshots.hexdigest(),
            }
    if not {"audit.sqlite", "access.sqlite"} <= set(result):
        raise ValueError("Required Gateway audit/access state is missing")
    return result


def verify_state_restore(destination):
    destination = Path(destination).resolve()
    result = sqlite_reconciliation(
        destination / "state", destination / "runtime/gateway.env"
    )
    expected = json.loads((destination / "state-reconciliation.json").read_text())
    if result != expected:
        raise ValueError("Restored Gateway state reconciliation failed")
    return {
        "sqlite_integrity": "ok",
        "sqlite_files": len(result),
        "audit_events": result["audit.sqlite"]["tables"]["audit"]["rows"],
        "authenticated_snapshots": result["audit.sqlite"]["authenticated_snapshots"],
        "access_requests": result["access.sqlite"]["tables"]["access_requests"]["rows"],
    }


def private_write(path, data):
    """Exclusive creation prevents accidental overwrite of keys/backups."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def read_key(path, create=False):
    path = Path(path)
    if create and not path.exists():
        private_write(path, secrets.token_bytes(32))
    value = path.read_bytes()
    if len(value) != 32:
        raise ValueError("Backup key must contain exactly 32 bytes")
    return value


def seal(files, key):
    """files maps safe POSIX paths to (bytes, permission mode)."""
    if len(files) > 9999 or sum(len(content) for content, _ in files.values()) > MAX_ARCHIVE:
        raise ValueError("Backup expanded data exceeds capacity")
    manifest = {"schema": 1, "created_at": datetime.now(timezone.utc).isoformat(), "files": {}}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, (content, mode) in sorted(files.items()):
            safe_name(name)
            if len(content) > MAX_FILE:
                raise ValueError("Backup member exceeds size limit")
            entry = zipfile.ZipInfo(name)
            entry.external_attr = (stat.S_IFREG | (mode & 0o777)) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, content)
            manifest["files"][name] = {
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "mode": mode & 0o777,
            }
        archive.writestr("MANIFEST.json", json.dumps(manifest, sort_keys=True))
    plaintext = buffer.getvalue()
    if len(plaintext) > MAX_ARCHIVE:
        raise ValueError("Backup archive exceeds size limit")
    nonce = os.urandom(12)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, plaintext, MAGIC)


def safe_name(name):
    path = PurePosixPath(name)
    if (
        not name
        or name == "MANIFEST.json"
        or "\\" in name
        or ":" in name
        or path.is_absolute()
        or any(part in {"..", ".", ""} for part in name.split("/"))
    ):
        raise ValueError("Unsafe backup member path")
    return path


def inspect_backup(data, key):
    """Authenticate and verify every member before creating any destination."""
    if len(data) > MAX_ARCHIVE + 100 or not data.startswith(MAGIC):
        raise ValueError("Unsupported or oversized backup")
    offset = len(MAGIC)
    plain = AESGCM(key).decrypt(data[offset : offset + 12], data[offset + 12 :], MAGIC)
    files = {}
    with zipfile.ZipFile(io.BytesIO(plain)) as archive:
        names = archive.namelist()
        if len(names) > 10000 or len(names) != len(set(names)) or names.count("MANIFEST.json") != 1:
            raise ValueError("Ambiguous backup members")
        if archive.getinfo("MANIFEST.json").file_size > 4 * 1024 * 1024:
            raise ValueError("Oversized backup manifest")
        manifest = json.loads(archive.read("MANIFEST.json"))
        if manifest.get("schema") != 1 or set(names) != set(manifest["files"]) | {"MANIFEST.json"}:
            raise ValueError("Invalid backup manifest")
        expanded = 0
        for name, metadata in manifest["files"].items():
            safe_name(name)
            entry = archive.getinfo(name)
            expanded += entry.file_size
            if (
                entry.file_size > MAX_FILE
                or expanded > MAX_ARCHIVE
                or stat.S_ISLNK(entry.external_attr >> 16)
            ):
                raise ValueError("Unsafe backup member")
            content = archive.read(name)
            if (
                len(content) != metadata["size"]
                or hashlib.sha256(content).hexdigest() != metadata["sha256"]
            ):
                raise ValueError("Backup checksum mismatch")
            mode = metadata["mode"]
            if type(mode) is not int or not 0 <= mode <= 0o777:
                raise ValueError("Invalid file permissions")
            files[name] = (content, mode)
    return manifest, files


def restore_files(archive_path, key_path, destination):
    destination = Path(destination).resolve()
    if destination.exists():
        raise ValueError("Restore destination already exists; running state is never overwritten")
    manifest, files = inspect_backup(Path(archive_path).read_bytes(), read_key(key_path))
    destination.mkdir(parents=True, mode=0o700)
    for name, (content, mode) in files.items():
        target = destination.joinpath(*PurePosixPath(name).parts)
        if not target.resolve().is_relative_to(destination):
            raise ValueError("Restore path escaped destination")
        private_write(target, content)
        if os.name != "nt":
            target.chmod(mode)
    private_write(destination / "RESTORE_MANIFEST.json", json.dumps(manifest, indent=2).encode())
    return destination, manifest


def restart_services(compose, services, timeout=90):
    """Use portable Compose start and poll only previously running services.

    Compose versions differ in support/behavior of start --wait. Status JSON
    also changed from a JSON array to newline-delimited objects across versions.
    """
    if not services:
        return

    def command(*args):
        try:
            return compose(*args, capture_output=True, text=True)
        except subprocess.CalledProcessError as error:
            detail = error.stderr or error.stdout or f"exit status {error.returncode}"
            if isinstance(detail, bytes):
                detail = detail.decode("utf-8", errors="replace")
            raise ValueError(f"Compose {args[0]} failed during backup recovery: {detail.strip()[:2000]}") from error

    command("start", *services)
    deadline = time.monotonic() + timeout
    observed = {}
    while True:
        result = command("ps", "--all", "--format", "json", *services)
        try:
            try:
                records = json.loads(result.stdout or "[]")
            except json.JSONDecodeError:
                records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            if isinstance(records, dict):
                records = [records]
            if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
                raise ValueError("Expected Compose status objects")
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise ValueError("Invalid Compose JSON status during backup recovery") from error
        observed = {
            service: [
                (str(row.get("State", "")).lower(), str(row.get("Health") or "").lower())
                for row in records if row.get("Service") == service
            ]
            for service in services
        }
        if all(
            states and all(state == "running" and health in {"", "none", "healthy"} for state, health in states)
            for states in observed.values()
        ):
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError(f"Backup service recovery timed out after {timeout}s: {observed}")
        time.sleep(min(1, remaining))


def create_backup(output=None):
    from scripts.portfolio import RUNTIME, compose

    directory = (RUNTIME / "backups").resolve()
    name = datetime.now(timezone.utc).strftime("gateway-%Y%m%dT%H%M%SZ.ztbackup")
    output = Path(output).resolve() if output else directory / name
    if not output.is_relative_to(directory) or output.exists():
        raise ValueError("New backups must be created inside .gateway/backups without overwrite")
    # Coordinate with the ordinary activation CLI; direct administrator file writes
    # are outside this local-controller consistency boundary.
    lock = RUNTIME / "server/releases/.activation.lock"
    handle = lock.open("x")
    running = []
    try:
        services = compose(
            "ps", "--status", "running", "--services", capture_output=True, text=True
        ).stdout.splitlines()
        if "postgres" not in services:
            raise ValueError("PostgreSQL must be running for a consistent backup")
        running = [service for service in ("proxy", "gateway") if service in services]
        if running:
            compose("stop", "--timeout", "30", *running, capture_output=True)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            state.mkdir()
            compose("cp", "gateway:/state/.", str(state), capture_output=True)
            dump = compose(
                "exec",
                "-T",
                "postgres",
                "pg_dump",
                "-U",
                "gateway_owner",
                "-d",
                "gateway_db",
                "-Fc",
                capture_output=True,
            ).stdout
            reconciliation = compose(
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "gateway_owner",
                "-d",
                "gateway_db",
                "-At",
                "-c",
                RECONCILIATION_SQL,
                capture_output=True,
                text=True,
            ).stdout.strip()
            state_check = sqlite_reconciliation(state, RUNTIME / "gateway.env")
            files = {
                "database.dump": (dump, 0o600),
                "reconciliation.json": (reconciliation.encode(), 0o600),
                "state-reconciliation.json": (json.dumps(state_check).encode(), 0o600),
            }
            for parent, prefix in ((RUNTIME, "runtime"), (state, "state")):
                for path in parent.rglob("*"):
                    relative = path.relative_to(parent)
                    if (
                        not path.is_file()
                        or path.is_symlink()
                        or any(
                            part in {"backups", "restored", "state"} for part in relative.parts[:-1]
                        )
                    ):
                        continue
                    if (
                        path.name in {"backup.key", ".activation.lock"}
                        or path.suffix == ".ztbackup"
                    ):
                        continue
                    files[prefix + "/" + relative.as_posix()] = (
                        path.read_bytes(),
                        stat.S_IMODE(path.stat().st_mode),
                    )
            encrypted = seal(files, read_key(RUNTIME / "backup.key", create=True))
            private_write(output, encrypted)
    finally:
        handle.close()
        lock.unlink()
        if running:
            restart_services(compose, list(reversed(running)))
    return output


def verify_database_restore(destination, image="postgres:16-alpine"):
    """Start a disposable network-isolated PostgreSQL; remove only that container."""
    destination = Path(destination).resolve()
    dump = destination / "database.dump"
    if not dump.is_file():
        raise ValueError("Restored database dump missing")
    name = "abac-restore-" + uuid4().hex

    def docker(*args, **kwargs):
        return subprocess.run(["docker", *args], check=True, capture_output=True, **kwargs)

    created = False
    try:
        docker(
            "run",
            "--name",
            name,
            "--network",
            "none",
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "-e",
            "POSTGRES_USER=gateway_owner",
            "-e",
            "POSTGRES_DB=gateway_db",
            "-d",
            image,
        )
        created = True
        for _ in range(60):
            ready = subprocess.run(
                [
                    "docker",
                    "exec",
                    name,
                    "sh",
                    "-c",
                    'test "$(cat /proc/1/comm)" = postgres && pg_isready -U gateway_owner -d gateway_db',
                ],
                capture_output=True,
            )
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Isolated restore PostgreSQL did not become ready")
        docker(
            "exec",
            name,
            "psql",
            "-U",
            "gateway_owner",
            "-d",
            "gateway_db",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "CREATE ROLE gateway_reader; CREATE ROLE gateway_session;",
        )
        docker("cp", str(dump), name + ":/tmp/database.dump")
        docker(
            "exec",
            name,
            "pg_restore",
            "--exit-on-error",
            "--no-owner",
            "-U",
            "gateway_owner",
            "-d",
            "gateway_db",
            "/tmp/database.dump",
        )
        result = docker(
            "exec",
            name,
            "psql",
            "-U",
            "gateway_owner",
            "-d",
            "gateway_db",
            "-At",
            "-c",
            RECONCILIATION_SQL,
            text=True,
        )
        evidence = json.loads(result.stdout)
        expected = json.loads((destination / "reconciliation.json").read_text())
        flags = ("force_rls_tables", "rls_enabled_tables", "tenant_policy_count", "scope_policy_count")
        if (
            any(evidence.get(flag) != 3 for flag in flags)
            or evidence.get("reader_role_safe") is not True
            or any(
                row.get("select") is not True
                or any(row.get(permission) is not False for permission in ("insert", "update", "delete"))
                for row in evidence.get("reader_privileges", [])
            )
            or len(evidence.get("reader_privileges", [])) != 3
            or evidence.get("session_role_permissions")
            != {"select": True, "insert": True, "delete": True, "update": False}
            or evidence != expected
        ):
            raise ValueError("Restored database reconciliation failed")
        no_context = docker(
            "exec", name, "psql", "-U", "gateway_owner", "-d", "gateway_db", "-qAt",
            "-v", "ON_ERROR_STOP=1", "-c",
            "SET ROLE gateway_reader; SELECT json_build_object("
            "'customers',(SELECT count(*) FROM customer_data),"
            "'financial',(SELECT count(*) FROM financial_records),"
            "'production',(SELECT count(*) FROM production_logs));",
            text=True,
        )
        if json.loads(no_context.stdout) != {"customers": 0, "financial": 0, "production": 0}:
            raise ValueError("Restored reader can access rows without context")
        return {
            "isolated_network": "none",
            "restored": True,
            "counts": {key: value for key, value in evidence.items() if not key.endswith("fingerprint")},
            "reader_without_context_rows": 0,
            "state": verify_state_restore(destination),
        }
    finally:
        if created:
            docker("rm", "-f", "-v", name)


def main():
    from scripts.portfolio import RUNTIME

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--output", type=Path)
    restore = commands.add_parser("restore")
    restore.add_argument("archive", type=Path)
    restore.add_argument("--key", type=Path, default=RUNTIME / "backup.key")
    restore.add_argument("--destination", type=Path, required=True)
    restore.add_argument("--verify-db", action="store_true")
    restore.add_argument(
        "--report", type=Path,
        help="Write public verification counts/flags as JSON; requires --verify-db",
    )
    args = parser.parse_args()
    if args.command == "restore" and args.report and not args.verify_db:
        parser.error("--report requires --verify-db so reports include actual isolated verification")
    if args.command == "create":
        path = create_backup(args.output)
        print("Encrypted backup created:", path)
        print("Keep .gateway/backup.key separately; it is not inside the backup.")
    else:
        destination, manifest = restore_files(args.archive, args.key, args.destination)
        print("Restored to new directory:", destination)
        print("Verified files:", len(manifest["files"]))
        if args.verify_db:
            result = verify_database_restore(destination)
            print(json.dumps(result, indent=2))
            if args.report:
                from app.gateway.releases import atomic_json

                # result deliberately contains only public counts/flags and fixed
                # table names; decrypted rows, fingerprints, keys and paths stay private.
                atomic_json(args.report, {
                    "executed_at": datetime.now(timezone.utc).isoformat(),
                    "verified_files": len(manifest["files"]),
                    **result,
                })


if __name__ == "__main__":
    main()
