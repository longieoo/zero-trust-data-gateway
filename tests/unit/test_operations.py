"""Deployment identity validation prevents accidental reuse of another project's volumes."""

import pytest

from scripts import portfolio


def test_compose_project_reads_runtime_identity_without_exposing_other_values(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("GATEWAY_COMPOSE_PROJECT", raising=False)
    monkeypatch.setattr(portfolio, "RUNTIME", tmp_path)
    (tmp_path / "gateway.env").write_text(
        "SECRET=not-printed\nGATEWAY_COMPOSE_PROJECT=abac-complete\n"
    )
    assert portfolio.compose_project() == "abac-complete"


def test_explicit_project_environment_has_precedence(tmp_path, monkeypatch):
    monkeypatch.setattr(portfolio, "RUNTIME", tmp_path)
    (tmp_path / "gateway.env").write_text("GATEWAY_COMPOSE_PROJECT=abac-stored\n")
    monkeypatch.setenv("GATEWAY_COMPOSE_PROJECT", "abac-explicit")
    assert portfolio.compose_project() == "abac-explicit"


@pytest.mark.parametrize("value", ["../existing", "ABAC", "abac;exit", "-project", "", "a" * 64])
def test_invalid_project_identity_rejected(value):
    with pytest.raises(ValueError):
        portfolio.valid_project(value)
