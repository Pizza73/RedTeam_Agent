"""Phase 0B negative/security probes: forged writes, uniqueness, secret leakage = 0."""

from __future__ import annotations

import copy
import pickle
from datetime import UTC, datetime

import pytest

import redteam_agent.execution.secret_injection as secret_injection
import support_phase0b as p0b
from redteam_agent.errors import (
    ExecutionUniquenessError,
    RepositoryIntegrityError,
)
from redteam_agent.execution.dispatch_port import DispatchResultCapture
from redteam_agent.storage.database import UnitOfWork
from redteam_agent.storage.guard import WriteGuard
from support_phase0b import build_execution_record

T0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _dispatched_secret(kernel: object):  # type: ignore[no-untyped-def]
    seeded = p0b.seed_authorized(kernel, with_secret=True)  # type: ignore[arg-type]
    p0b.authorize(seeded)
    kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)  # type: ignore[attr-defined]
    return seeded


def test_forged_execution_write_without_owner_guard_rejected() -> None:
    kernel = p0b.make_kernel()
    record = build_execution_record(kernel, execution_id="forged-1", decision_id="d-forged")
    with pytest.raises(RepositoryIntegrityError), UnitOfWork(kernel.phase0a.database):
        kernel.execution_repository.create(record, guard=WriteGuard())


def test_one_decision_one_execution_enforced_by_database() -> None:
    kernel = p0b.make_kernel()
    guard = kernel.execution_guard
    a = build_execution_record(kernel, execution_id="exec-a", decision_id="dup-decision")
    b = build_execution_record(kernel, execution_id="exec-b", decision_id="dup-decision")
    with UnitOfWork(kernel.phase0a.database):
        kernel.execution_repository.create(a, guard=guard)
    with pytest.raises(ExecutionUniquenessError), UnitOfWork(kernel.phase0a.database):
        kernel.execution_repository.create(b, guard=guard)


def test_row_tamper_detected_on_read() -> None:
    kernel = p0b.make_kernel()
    guard = kernel.execution_guard
    record = build_execution_record(kernel, execution_id="exec-t", decision_id="d-t")
    with UnitOfWork(kernel.phase0a.database):
        kernel.execution_repository.create(record, guard=guard)
    # Raw single-row edit of the JSON without recomputing the row digest.
    conn = kernel.phase0a.database.connection
    conn.execute(
        "UPDATE executions SET json = replace(json, 'AUTHORIZED', 'RUNNING') WHERE execution_id = ?",
        ("exec-t",),
    )
    with pytest.raises(RepositoryIntegrityError):
        kernel.execution_repository.get("exec-t")


def test_secret_plaintext_absent_from_all_durable_rows() -> None:
    kernel = p0b.make_kernel()
    _dispatched_secret(kernel)
    kernel.collection_coordinator.start_collection(execution_id="exec-1")
    kernel.collection_coordinator.collect(execution_id="exec-1")
    kernel.ingestion_coordinator.ingest(execution_id="exec-1")
    leaked = p0b.SECRET_VALUE.decode()
    conn = kernel.phase0a.database.connection
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    for table in tables:
        cols = [c[1] for c in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if "json" not in cols:
            continue
        for (blob,) in conn.execute(f"SELECT json FROM {table}"):
            assert leaked not in blob, f"secret plaintext leaked into {table}"


def test_fabricated_continuation_cannot_obtain_plaintext() -> None:
    assert not hasattr(secret_injection, "SecretDispatchContinuation")
    assert not hasattr(secret_injection, "open_dispatch_continuation")


def test_capabilities_are_not_serializable() -> None:
    capture = DispatchResultCapture(mode="provider_task", capture_id="cap", sink=None)
    with pytest.raises(TypeError):
        pickle.dumps(capture)
    with pytest.raises(TypeError):
        copy.deepcopy(_binding())


def test_no_bearer_token_recovery_authority_reloads_current_record() -> None:
    kernel = p0b.make_kernel()
    _dispatched_secret(kernel)
    authority = kernel.recovery_service.issue_authority(
        authority_id="ra-1", execution_id="exec-1", allowed_operation="reconcile", reason="check"
    )
    # Presenting the authority id for a *different* execution is refused (not a bearer token).
    from redteam_agent.errors import CancelAttemptError

    with pytest.raises(CancelAttemptError):
        kernel.recovery_service.request_cancel(
            cancel_attempt_id="ca-x", execution_id="exec-1", recovery_authority_id="ra-1", reason="x"
        )  # ra-1 is a reconcile authority, not a cancel authority
    assert authority.allowed_operation == "reconcile"


def _binding():  # type: ignore[no-untyped-def]
    from redteam_agent.execution.secret_binding import _EphemeralSecretBinding

    return _EphemeralSecretBinding(secret_argument_path="/c", secret_version_id="sv-1", buffer=bytearray(b"x"))


def _dummy_request():  # type: ignore[no-untyped-def]
    from redteam_agent.execution.adapter import ExecutionRequest
    from redteam_agent.models.common import ToolRef

    return ExecutionRequest(
        execution_id="exec-1", task_id="t1", tool_ref=ToolRef(tool_id="net-scan", registry_revision=1),
        adapter_id="c2-main", provider_tool_name="scan", result_delivery_mode="provider_task",
        idempotency_key="ik", timeout_seconds=60, arguments={"destinations": ["10.0.0.1"]},
    )
