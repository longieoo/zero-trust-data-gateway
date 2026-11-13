"""Backup confidentiality, archive integrity and non-destructive restore boundaries."""

import io
import json
import os
import stat
import sqlite3
import zipfile

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts.backup_restore import MAGIC, inspect_backup, private_write, restore_files, seal

KEY = b"a" * 32


def encrypted_archive(entries, manifest):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
        archive.writestr("MANIFEST.json", json.dumps(manifest))
    nonce = b"n" * 12
    return MAGIC + nonce + AESGCM(KEY).encrypt(nonce, stream.getvalue(), MAGIC)


def test_backup_encrypts_secrets_and_restores_permissions(tmp_path):
    files = {
        "runtime/gateway.env": (b"PRIVATE_TEST_PASSWORD=secret-example", 0o600),
        "state/audit.sqlite": (b"synthetic database bytes", 0o640),
    }
    encrypted = seal(files, KEY)
    assert b"secret-example" not in encrypted
    path, key = tmp_path / "backup.ztbackup", tmp_path / "backup.key"
    private_write(path, encrypted)
    private_write(key, KEY)
    destination, manifest = restore_files(path, key, tmp_path / "restore")
    for name, (expected, mode) in files.items():
        assert (destination / name).read_bytes() == expected
        if os.name != "nt":
            assert stat.S_IMODE((destination / name).stat().st_mode) == mode
    assert len(manifest["files"]) == 2


def test_restore_authenticates_before_creating_directory(tmp_path):
    encrypted = bytearray(seal({"runtime/key": (b"demo", 0o600)}, KEY))
    encrypted[-1] ^= 1
    archive, key, destination = tmp_path / "backup", tmp_path / "key", tmp_path / "restored"
    private_write(archive, encrypted)
    private_write(key, KEY)
    with pytest.raises(Exception):
        restore_files(archive, key, destination)
    assert not destination.exists()


def test_restore_cannot_overwrite_existing_state(tmp_path):
    destination = tmp_path / "existing"
    destination.mkdir()
    marker = destination / "important"
    marker.write_text("keep")
    with pytest.raises(ValueError, match="already exists"):
        restore_files(tmp_path / "missing", tmp_path / "key", destination)
    assert marker.read_text() == "keep"


@pytest.mark.parametrize("name", ["../secret", "/etc/passwd", "C:/secret", "a\\b", "a//b", "a/./b"])
def test_restore_rejects_unsafe_authenticated_paths(name):
    payload = encrypted_archive(
        {name: b"x"},
        {"schema": 1, "files": {name: {"size": 1, "sha256": "invalid", "mode": 0o600}}},
    )
    with pytest.raises(ValueError):
        inspect_backup(payload, KEY)


def test_restore_rejects_authenticated_content_with_wrong_checksum():
    payload = encrypted_archive(
        {"runtime/config": b"changed"},
        {"schema": 1, "files": {"runtime/config": {"size": 7, "sha256": "0" * 64, "mode": 0o600}}},
    )
    with pytest.raises(ValueError, match="checksum"):
        inspect_backup(payload, KEY)


def test_backup_key_is_not_replaced_by_exclusive_write(tmp_path):
    path = tmp_path / "backup.key"
    private_write(path, KEY)
    with pytest.raises(FileExistsError):
        private_write(path, b"b" * 32)
    assert path.read_bytes() == KEY


def test_wrong_key_cannot_read_backup():
    encrypted = seal({"runtime/config": (b"secret", 0o600)}, KEY)
    with pytest.raises(Exception):
        inspect_backup(encrypted, b"b" * 32)


@pytest.fixture
def sqlite_restore_layout(tmp_path):
    from app.gateway.access import AccessStore
    from app.gateway.audit import AuditStore
    from scripts.backup_restore import sqlite_reconciliation

    state = tmp_path / "state"
    state.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    environment = runtime / "gateway.env"
    environment.write_text("GATEWAY_AUDIT_KEY=" + "ab" * 32 + "\n")
    audit = AuditStore(state / "audit.sqlite", "ab" * 32)
    audit.append(
        "test-request", "intent", {"resource": "customers"},
        {"sensitive_fixture": "snapshot must remain confidential"},
        tenant="demo", subject="analyst",
    )
    access = AccessStore(state / "access.sqlite")
    access.create(
        {"id": "analyst", "tenant_id": "demo", "role": "marketing_analyst",
         "department": "marketing", "clearance": "confidential"},
        "production", "Review assigned production data", 900,
    )
    expected = sqlite_reconciliation(state, environment)
    (tmp_path / "state-reconciliation.json").write_text(json.dumps(expected))
    return tmp_path


def test_restore_validates_access_audit_and_authenticated_snapshots(sqlite_restore_layout):
    from scripts.backup_restore import verify_state_restore

    assert verify_state_restore(sqlite_restore_layout) == {
        "sqlite_integrity": "ok", "sqlite_files": 2,
        "audit_events": 1, "authenticated_snapshots": 1, "access_requests": 1,
    }


def test_restore_rejects_changed_access_state(sqlite_restore_layout):
    from scripts.backup_restore import verify_state_restore

    with sqlite3.connect(sqlite_restore_layout / "state/access.sqlite") as database:
        database.execute("UPDATE access_requests SET purpose='tampered grant purpose'")
    with pytest.raises(ValueError, match="state reconciliation"):
        verify_state_restore(sqlite_restore_layout)


def test_restore_cannot_decrypt_snapshots_with_wrong_audit_key(sqlite_restore_layout):
    from cryptography.exceptions import InvalidTag
    from scripts.backup_restore import verify_state_restore

    (sqlite_restore_layout / "runtime/gateway.env").write_text(
        "GATEWAY_AUDIT_KEY=" + "cd" * 32 + "\n"
    )
    with pytest.raises(InvalidTag):
        verify_state_restore(sqlite_restore_layout)


def test_restore_rejects_audit_snapshot_identity_tampering(sqlite_restore_layout):
    from cryptography.exceptions import InvalidTag
    from scripts.backup_restore import verify_state_restore

    with sqlite3.connect(sqlite_restore_layout / "state/audit.sqlite") as database:
        database.execute("UPDATE audit SET tenant='other-tenant'")
    with pytest.raises(InvalidTag):
        verify_state_restore(sqlite_restore_layout)


def test_restore_cli_writes_public_machine_readable_report(tmp_path, monkeypatch):
    import sys
    from scripts import backup_restore

    report = tmp_path / "public/recovery.json"
    destination = tmp_path / "private-restore"
    monkeypatch.setattr(
        backup_restore, "restore_files",
        lambda *args: (destination, {"files": {"runtime/private.key": {}, "state/audit.sqlite": {}}}),
    )
    safe = {
        "isolated_network": "none", "restored": True,
        "counts": {"customers": 3, "force_rls_tables": 3},
        "reader_without_context_rows": 0,
        "state": {"sqlite_integrity": "ok", "authenticated_snapshots": 1},
    }
    monkeypatch.setattr(backup_restore, "verify_database_restore", lambda *args: safe)
    monkeypatch.setattr(sys, "argv", [
        "backup_restore", "restore", "private-archive", "--destination", str(destination),
        "--verify-db", "--report", str(report),
    ])
    backup_restore.main()
    value = json.loads(report.read_text())
    assert value["verified_files"] == 2
    assert value["executed_at"].endswith("+00:00")
    assert all(value[key] == expected for key, expected in safe.items())
    assert str(tmp_path) not in report.read_text()
    assert "private" not in report.read_text()


def test_restore_report_requires_isolated_verification(tmp_path, monkeypatch):
    import sys
    from scripts import backup_restore

    monkeypatch.setattr(sys, "argv", [
        "backup_restore", "restore", "private-archive", "--destination", str(tmp_path / "restore"),
        "--report", str(tmp_path / "recovery.json"),
    ])
    with pytest.raises(SystemExit) as error:
        backup_restore.main()
    assert error.value.code == 2
    assert not (tmp_path / "restore").exists()


def test_failed_database_dump_restarts_previous_services_and_releases_lock(tmp_path, monkeypatch):
    import subprocess
    from types import SimpleNamespace
    from scripts import portfolio
    from scripts.backup_restore import create_backup

    runtime = tmp_path / ".gateway"
    (runtime / "server/releases").mkdir(parents=True)
    monkeypatch.setattr(portfolio, "RUNTIME", runtime)
    calls = []

    def compose(*args, **kwargs):
        calls.append(args)
        if args[0] == "ps":
            if "--format" in args:
                return SimpleNamespace(stdout=json.dumps([
                    {"Service": "gateway", "State": "running", "Health": "healthy"},
                    {"Service": "proxy", "State": "running", "Health": ""},
                ]))
            return SimpleNamespace(stdout="postgres\ngateway\nproxy\n")
        if "pg_dump" in args:
            raise subprocess.CalledProcessError(1, ["pg_dump"])
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(portfolio, "compose", compose)
    with pytest.raises(subprocess.CalledProcessError):
        create_backup(runtime / "backups/test.ztbackup")
    assert ("stop", "--timeout", "30", "proxy", "gateway") in calls
    assert ("start", "gateway", "proxy") in calls
    assert all("--wait" not in call and "--wait-timeout" not in call for call in calls)
    assert not (runtime / "server/releases/.activation.lock").exists()
    assert not (runtime / "backups/test.ztbackup").exists()


@pytest.mark.parametrize("format", ["array", "ndjson"])
def test_backup_restart_polls_portable_status_until_services_healthy(monkeypatch, format):
    from types import SimpleNamespace
    from scripts.backup_restore import restart_services

    calls = []
    statuses = iter([
        [{"Service": "gateway", "State": "running", "Health": "starting"},
         {"Service": "proxy", "State": "running", "Health": ""}],
        [{"Service": "gateway", "State": "running", "Health": "healthy"},
         {"Service": "proxy", "State": "running", "Health": ""},
         {"Service": "unrelated", "State": "exited", "Health": "unhealthy"}],
    ])

    def compose(*args, **kwargs):
        calls.append(args)
        if args[0] == "start":
            return SimpleNamespace(stdout="")
        records = next(statuses)
        text = json.dumps(records) if format == "array" else "\n".join(map(json.dumps, records))
        return SimpleNamespace(stdout=text)

    monkeypatch.setattr("scripts.backup_restore.time.sleep", lambda seconds: None)
    restart_services(compose, ["gateway", "proxy"])
    assert calls == [
        ("start", "gateway", "proxy"),
        ("ps", "--all", "--format", "json", "gateway", "proxy"),
        ("ps", "--all", "--format", "json", "gateway", "proxy"),
    ]


@pytest.mark.parametrize("records", [
    [],
    [{"Service": "gateway", "State": "exited", "Health": ""}],
    [{"Service": "gateway", "State": "running", "Health": "unhealthy"}],
])
def test_backup_restart_fails_when_previously_running_service_does_not_recover(records):
    from types import SimpleNamespace
    from scripts.backup_restore import restart_services

    def compose(*args, **kwargs):
        return SimpleNamespace(stdout=json.dumps(records) if args[0] == "ps" else "")

    with pytest.raises(ValueError, match="recovery timed out"):
        restart_services(compose, ["gateway"], timeout=0)


@pytest.mark.parametrize("command", ["start", "ps"])
def test_backup_restart_surfaces_compose_stderr(command):
    import subprocess
    from types import SimpleNamespace
    from scripts.backup_restore import restart_services

    def compose(*args, **kwargs):
        if args[0] == command:
            raise subprocess.CalledProcessError(1, ["compose", *args], stderr="unsupported test option")
        return SimpleNamespace(stdout="")

    with pytest.raises(ValueError, match=f"Compose {command} failed.*unsupported test option"):
        restart_services(compose, ["gateway"])


def test_backup_restart_rejects_malformed_status_output():
    from types import SimpleNamespace
    from scripts.backup_restore import restart_services

    def compose(*args, **kwargs):
        return SimpleNamespace(stdout="invalid-json" if args[0] == "ps" else "")

    with pytest.raises(ValueError, match="Invalid Compose JSON"):
        restart_services(compose, ["gateway"])
