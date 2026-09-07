"""Repository write/read integrity tests (B-06 / H-03 / D / G)."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

import support
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.errors import (
    DigestIntegrityError,
    DuplicateJsonKeyError,
    RepositoryIntegrityError,
)
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.runtime.clock import ManualClock
from redteam_agent.session.models import SessionSecurityContext, SessionSecurityContextSnapshot
from redteam_agent.storage.integrity import verify_object_integrity


def _kernel():
    return build_test_kernel(clock=ManualClock(support.T0))


def _running_with_decision(kernel):
    tool = support.network_tool()
    revision = support.mission_revision(kernel.digest_service, profile=support.make_profile(kernel.digest_service))
    seeded = support.seed_running_mission(kernel, tool=tool, revision=revision)
    proposal = support.make_proposal(
        tool=seeded.tool, arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    return seeded, decision


def test_decision_reads_back_intact() -> None:
    kernel = _kernel()
    _seeded, decision = _running_with_decision(kernel)
    loaded = kernel.decision_repository.get(decision.decision_id)
    assert loaded == decision


def test_tampered_decision_row_fails_integrity() -> None:
    kernel = _kernel()
    _seeded, decision = _running_with_decision(kernel)
    payload = json.loads(decision.model_dump_json())
    payload["effective_risk"] = "high"  # tamper a stored field without fixing decision_digest
    kernel.database.overwrite("policy_decisions", decision.decision_id, json.dumps(payload))
    with pytest.raises(DigestIntegrityError):
        kernel.decision_repository.get(decision.decision_id)


def test_row_key_swap_rejected() -> None:
    kernel = _kernel()
    _seeded, decision = _running_with_decision(kernel)
    # Store the decision payload under a different row key.
    kernel.database.overwrite("policy_decisions", "wrong-key", decision.model_dump_json())
    with pytest.raises(RepositoryIntegrityError):
        kernel.decision_repository.get("wrong-key")


def test_invalid_model_rejected_without_leaking_input() -> None:
    import warnings

    kernel = _kernel()
    profile = support.make_profile(kernel.digest_service)
    kernel.profile_repository.save(profile)
    revision = support.mission_revision(kernel.digest_service, profile=profile)
    marker = "SYNTHETIC_SECRET_SHOULD_NOT_LEAK"
    # model_copy(update=...) bypasses validation, injecting an invalid value.
    bad = revision.model_copy(update={"max_iterations": marker})
    support.provision_lifecycle_roles(kernel)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(RepositoryIntegrityError) as exc_info:
            kernel.mission_manager.create_mission(bad, actor_token=support.ADMIN_ACTOR_TOKEN)
    # The synthetic secret must not appear in the exception, its chain, or any warning.
    assert marker not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert all(marker not in str(w.message) for w in caught)


def test_invalid_nested_model_rejected_without_serializer_warning() -> None:
    import warnings

    kernel = _kernel()
    marker = "SYNTHETIC_NESTED_SECRET_SHOULD_NOT_LEAK"
    snapshot = support.session_snapshot()
    bad_context = snapshot.context.model_copy(update={"current_principal": {"value": marker}})
    bad_snapshot = snapshot.model_copy(update={"context": bad_context})
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(RepositoryIntegrityError) as exc_info:
            kernel.session_repository.save(bad_snapshot)
    assert kernel.database.get("session_security_context_snapshots", snapshot.session_id) is None
    assert marker not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert all(marker not in str(item.message) for item in caught)


def test_model_copy_nested_unknown_field_rejected() -> None:
    kernel = _kernel()
    snapshot = support.session_snapshot()
    bad_context = snapshot.context.model_copy(update={"undeclared_authority": "hidden"})
    with pytest.raises(RepositoryIntegrityError):
        kernel.session_repository.save(snapshot.model_copy(update={"context": bad_context}))


def test_unknown_family_fails_closed() -> None:
    class _Unregistered(StrictImmutableBoundaryModel):
        value: int

    with pytest.raises(RepositoryIntegrityError):
        verify_object_integrity(_Unregistered(value=1), DigestService())


def test_profile_with_arbitrary_digest_fails_integrity() -> None:
    kernel = _kernel()
    profile = support.make_profile(kernel.digest_service)
    payload = json.loads(profile.model_dump_json())
    payload["profile_digest"] = "arbitrary-non-empty"
    kernel.database.overwrite("llm_profiles", profile.profile_revision, json.dumps(payload))
    with pytest.raises(DigestIntegrityError):
        kernel.profile_repository.get(profile.profile_revision)


def test_session_snapshot_identity_mismatch_rejected() -> None:
    context = SessionSecurityContext(
        session_id="sess-a",
        host="h",
        os="linux",
        architecture="x86_64",
        current_principal="user",
        effective_privilege_context="standard",
        session_capabilities=frozenset(),
        network_context="internal",
        security_status="ok",
    )
    with pytest.raises(ValidationError):
        SessionSecurityContextSnapshot(
            session_id="sess-b", context=context, session_fresh_until=support.T0, observed_at=support.T0
        )


def test_bulk_read_rejects_duplicate_keys() -> None:
    kernel = _kernel()
    # Craft a role-assignment row with a duplicate JSON key.
    raw = '{"mission_id": "mission-1", "mission_id": "mission-1", "principal_id": "p", "role": "approver", "active": true}'
    kernel.database.overwrite("mission_role_assignments", "mission-1/p/approver", raw)
    with pytest.raises(DuplicateJsonKeyError):
        kernel.role_assignment_repository.assignments_for("mission-1")


def test_idempotent_conflict_rejected() -> None:
    kernel = _kernel()
    ds = kernel.digest_service
    reg_a, _tools_a, _cat_a = support.build_registered_registry(
        ds, (support.network_tool(tool_id="a"),), catalog=kernel.contract_catalog, rule_catalog=kernel.rule_catalog
    )
    reg_b, _tools_b, _cat_b = support.build_registered_registry(
        ds, (support.network_tool(tool_id="b"),), catalog=kernel.contract_catalog, rule_catalog=kernel.rule_catalog
    )
    kernel.registry_repository.save(reg_a)
    with pytest.raises(RepositoryIntegrityError):
        kernel.registry_repository.save(reg_b)  # same revision key, different payload
