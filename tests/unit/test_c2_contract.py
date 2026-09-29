"""Provider-neutral C2 adapter contract tests (SystemDesign §13).

These probe the *contract* only: the untrusted observation boundary model and
the structural adapter surface. No provider is contacted and nothing is
dispatched; the Tuoni foundation is used purely as a conforming placeholder.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from redteam_agent.adapters.c2 import C2Adapter, C2SessionObservation
from redteam_agent.adapters.tuoni import (
    TuoniAdapterFoundation,
    build_tuoni_foundation_profile,
)
from redteam_agent.canonical.digest_service import DigestService

# The full structural surface a C2 adapter must expose (ExecutionAdapter core
# plus the two session-observation extensions).
_C2_ADAPTER_METHODS = (
    "identity",
    "get_capabilities",
    "submit",
    "reconcile",
    "cancel",
    "collect_result",
    "get_task_control",
    "list_sessions",
    "get_session",
)


def _observation(**overrides: Any) -> C2SessionObservation:
    fields: dict[str, Any] = {
        "provider_session_id": "provider-session-1",
        "provider_status": "active",
        "host": "target-1",
        "os": "linux",
        "architecture": "x86_64",
        "current_principal": "labuser",
        "capabilities": frozenset({"session.list"}),
        "observed_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    fields.update(overrides)
    return C2SessionObservation(**fields)


def test_session_observation_is_immutable() -> None:
    observation = _observation()
    with pytest.raises(ValidationError):
        observation.provider_status = "lost"  # type: ignore[misc]


def test_session_observation_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        _observation(smuggled="value")


@pytest.mark.parametrize(
    "field, value",
    [
        ("provider_status", "compromised"),
        ("os", "solaris"),
        ("provider_session_id", ""),
    ],
)
def test_session_observation_rejects_out_of_contract_values(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        _observation(**{field: value})


def test_session_observation_is_provider_neutral() -> None:
    # The model must not name any specific product; it carries only neutral
    # provider-facing identifiers so Core/Planner never depend on one C2.
    field_names = set(C2SessionObservation.model_fields)
    assert "tuoni" not in " ".join(field_names).lower()
    assert field_names == {
        "provider_session_id",
        "provider_status",
        "host",
        "os",
        "architecture",
        "current_principal",
        "capabilities",
        "observed_at",
    }


def test_foundation_structurally_satisfies_the_c2_adapter_contract() -> None:
    ds = DigestService()
    # The annotation makes the static type checker verify structural conformance
    # of every ExecutionAdapter/C2Adapter method signature.
    adapter: C2Adapter = TuoniAdapterFoundation(
        build_tuoni_foundation_profile(digest_service=ds), ds
    )
    for method_name in _C2_ADAPTER_METHODS:
        assert callable(getattr(adapter, method_name)), method_name
