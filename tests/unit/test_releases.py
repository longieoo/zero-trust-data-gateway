import base64
import json
import os
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.gateway.releases import (
    ReleaseRepository,
    atomic_json,
    digest,
    local_release,
    sign_release,
    verify_release,
)
from app.services import ROOT


@pytest.fixture
def signed():
    keys = {name: Ed25519PrivateKey.generate() for name in ("author", "reviewer")}
    trust = {
        name: base64.b64encode(key.public_key().public_bytes_raw()).decode()
        for name, key in keys.items()
    }
    release = local_release(json.loads((ROOT / "policies/policies.json").read_text()))
    for name, key in keys.items():
        sign_release(release, name, key)
    return release, trust, keys


def test_two_independent_signatures_required(signed):
    release, trust, _ = signed
    verify_release(release, trust)
    del release["signatures"]["reviewer"]
    verify_release(release, trust, required=1)
    with pytest.raises(ValueError):
        verify_release(release, trust)


def test_key_alias_cannot_self_approve(signed):
    release, trust, _ = signed
    trust["reviewer"] = trust["author"]
    release["signatures"]["reviewer"] = release["signatures"]["author"]
    with pytest.raises(ValueError):
        verify_release(release, trust)


@pytest.mark.parametrize("field", ["view", "policies", "engine_revision"])
def test_tampered_signed_release_rejected(signed, field):
    release, trust, _ = signed
    if field == "view":
        release["payload"]["view"]["mask_admin"] = True
    elif field == "policies":
        release["payload"]["policies"][0]["effect"] = "Deny"
    else:
        release["payload"][field] = "a" * 64
    release["revision"] = digest(release["payload"])
    with pytest.raises(Exception):
        verify_release(release, trust)


def test_activation_compare_swap_rollback_and_lock_cleanup(signed, tmp_path):
    release, trust, keys = signed
    atomic_json(tmp_path / "trust.json", trust)
    repository = ReleaseRepository(tmp_path, tmp_path / "trust.json")
    atomic_json(tmp_path / (release["revision"] + ".json"), release)
    repository.activate(release["revision"], None)
    newer = deepcopy(release)
    newer["payload"]["view"]["mask_admin"] = True
    newer["revision"] = digest(newer["payload"])
    for name, key in keys.items():
        sign_release(newer, name, key)
    atomic_json(tmp_path / (newer["revision"] + ".json"), newer)
    with pytest.raises(ValueError):
        repository.activate(newer["revision"], "0" * 64)
    assert not (tmp_path / ".activation.lock").exists()
    repository.activate(newer["revision"], release["revision"])
    assert repository.active()["revision"] == newer["revision"]
    repository.activate(release["revision"], newer["revision"])
    assert repository.active()["revision"] == release["revision"]


@pytest.mark.parametrize("revision", ["../secret", "A" * 64, "", "0" * 63])
def test_revision_cannot_escape_release_directory(tmp_path, revision):
    with pytest.raises(ValueError):
        ReleaseRepository(tmp_path, tmp_path / "trust").read(revision)


def test_atomic_replace_failure_keeps_previous_pointer(tmp_path, monkeypatch):
    from app.gateway import releases

    path = tmp_path / "active.json"
    atomic_json(path, {"revision": "old"})

    def unavailable(*args):
        raise PermissionError("Simulated sharing violation")

    monkeypatch.setattr(releases.os, "replace", unavailable)
    monkeypatch.setattr(releases.time, "sleep", lambda _: None)
    with pytest.raises(PermissionError):
        atomic_json(path, {"revision": "new"})
    assert json.loads(path.read_text())["revision"] == "old"
    assert list(tmp_path.glob("*.tmp")) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows file sharing semantics")
def test_atomic_replace_retries_transient_windows_sharing_violation(tmp_path, monkeypatch):
    from app.gateway import releases

    path = tmp_path / "active.json"
    original = releases.os.replace
    calls = []

    def temporarily_unavailable(*args):
        calls.append(True)
        if len(calls) < 3:
            raise PermissionError("Simulated transient file reader")
        return original(*args)

    monkeypatch.setattr(releases.os, "replace", temporarily_unavailable)
    monkeypatch.setattr(releases.time, "sleep", lambda _: None)
    atomic_json(path, {"revision": "new"})
    assert len(calls) == 3
    assert json.loads(path.read_text())["revision"] == "new"
