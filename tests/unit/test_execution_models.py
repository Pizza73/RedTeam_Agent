"""Strict-model invariants for Phase 0B records (negative-schema coverage)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from redteam_agent.execution.models import (
    DispatchClaim,
    ExecutionRecord,
    MissionExecutionBudget,
    ResultCollectionStateRecord,
    ResultIngestionStateRecord,
    ResultTaskBinding,
)
from redteam_agent.models.common import ToolRef

T0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
_TR = ToolRef(tool_id="net-scan", registry_revision=1)
_BINDING_ADAPTER: TypeAdapter[ResultTaskBinding] = TypeAdapter(ResultTaskBinding)


def _claim(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "claim_id": "claim-1", "execution_id": "exec-1", "execution_state_version": 3, "policy_decision_id": "d1",
        "authorization_digest": "ad", "mission_revision": 1, "authorization_epoch": 0, "tool_ref": _TR,
        "resolved_adapter_id": "c2-main", "approval_request_id": None, "approval_record_id": None,
        "secret_version_bindings_digest": "svb", "secret_lifecycle_heads_digest": "slh", "issued_at": T0,
        "expires_at": T0, "claim_state": "unconsumed", "consumption_id": None, "consumed_at": None,
        "invalidated_at": None, "invalidation_reason": None, "record_digest": "rd",
    }
    base.update(overrides)
    return base


def test_unconsumed_claim_rejects_consumption_fields() -> None:
    with pytest.raises(ValidationError):
        DispatchClaim(**_claim(consumption_id="c1"))  # type: ignore[arg-type]


def test_consumed_claim_requires_consumption_identity() -> None:
    with pytest.raises(ValidationError):
        DispatchClaim(**_claim(claim_state="consumed"))  # type: ignore[arg-type]


def test_consumed_claim_rejects_invalidation_fields() -> None:
    with pytest.raises(ValidationError):
        DispatchClaim(
            **_claim(claim_state="consumed", consumption_id="c1", consumed_at=T0, invalidation_reason="x")  # type: ignore[arg-type]
        )


def test_invalidated_claim_requires_invalidation_identity() -> None:
    with pytest.raises(ValidationError):
        DispatchClaim(**_claim(claim_state="invalidated"))  # type: ignore[arg-type]


def test_valid_claim_states_accepted() -> None:
    DispatchClaim(**_claim())  # unconsumed
    DispatchClaim(**_claim(claim_state="consumed", consumption_id="c1", consumed_at=T0))  # type: ignore[arg-type]
    DispatchClaim(
        **_claim(claim_state="invalidated", invalidated_at=T0, invalidation_reason="secret stale")  # type: ignore[arg-type]
    )


def _record(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "execution_id": "exec-1", "task_id": "task-1", "execution_state_version": 1, "record_digest": "rd",
        "mission_id": "m1", "mission_revision": 1, "authorization_epoch": 0, "plan_id": "p1",
        "policy_decision_id": "d1", "proposal_digest": "pd", "authorization_digest": "ad", "tool_ref": _TR,
        "resolved_adapter_id": "c2-main", "idempotency_key": "ik", "adapter_capabilities_digest": "acd",
        "sandbox_capabilities_digest": "scd", "remote_mcp_trust_policy_digest": "rmtd",
        "provider_execution_state": "AUTHORIZED", "pre_dispatch_block_reason": None,
        "result_collection_state_id": None, "result_ingestion_state": "NOT_AVAILABLE",
        "raw_result_quarantine_id": None, "result_task_binding_id": None, "dispatch_attempts": 0,
        "created_at": T0, "updated_at": T0,
    }
    base.update(overrides)
    return base


def test_blocked_execution_requires_reason() -> None:
    with pytest.raises(ValidationError):
        ExecutionRecord(**_record(provider_execution_state="BLOCKED"))  # type: ignore[arg-type]


def test_non_blocked_execution_rejects_reason() -> None:
    with pytest.raises(ValidationError):
        ExecutionRecord(**_record(pre_dispatch_block_reason="SESSION_STALE"))  # type: ignore[arg-type]


def test_dispatch_attempts_capped_at_one() -> None:
    with pytest.raises(ValidationError):
        ExecutionRecord(**_record(dispatch_attempts=2))  # type: ignore[arg-type]


def test_authorized_execution_rejects_existing_dispatch_attempt() -> None:
    with pytest.raises(ValidationError):
        ExecutionRecord(**_record(dispatch_attempts=1))  # type: ignore[arg-type]


def test_non_secret_block_rejects_claimed_attempt() -> None:
    with pytest.raises(ValidationError):
        ExecutionRecord(
            **_record(  # type: ignore[arg-type]
                provider_execution_state="BLOCKED",
                pre_dispatch_block_reason="APPROVAL_INVALID",
                dispatch_attempts=1,
            )
        )


def test_committed_collection_requires_receipt_pair() -> None:
    with pytest.raises(ValidationError):
        ResultCollectionStateRecord(
            collection_state_id="cs", collection_id="c", execution_id="e", state_version=1,
            status="COMMITTED_METADATA_PENDING", receipt_id=None, receipt_digest=None,
            last_committed_chunk_sequence=1, last_progress_digest="p", updated_at=T0,
            record_digest="d",
        )


def test_pending_ingestion_requires_receipt_and_quarantine() -> None:
    with pytest.raises(ValidationError):
        ResultIngestionStateRecord(
            ingestion_id="i", execution_id="e", collection_id="c", state_version=1,
            status="PENDING", receipt_id=None, receipt_digest=None, quarantine_id=None,
            attempt_count=0, manifest_id=None, manifest_digest=None, ingested_durable_at=None,
            evidence_retention_until=T0, updated_at=T0, record_digest="d",
        )


def _provider_binding() -> dict[str, object]:
    return {
        "binding_type": "provider_task", "task_id": "t1", "execution_id": "exec-1",
        "adapter_identity_digest": "aid", "provider_identity_digest": "pid", "provider_task_id": "pt1",
        "dispatch_claim_id": "claim-1", "binding_digest": "bd",
    }


def _local_binding() -> dict[str, object]:
    return {
        "binding_type": "local_result", "task_id": "t1", "execution_id": "exec-1",
        "adapter_identity_digest": "aid", "dispatch_claim_id": "claim-1", "capture_id": "cap1",
        "binding_digest": "bd",
    }


def test_both_binding_branches_accepted() -> None:
    provider = _BINDING_ADAPTER.validate_python(_provider_binding())
    local = _BINDING_ADAPTER.validate_python(_local_binding())
    assert provider.binding_type == "provider_task"
    assert local.binding_type == "local_result"


def test_local_capture_alias_rejected() -> None:
    payload = _local_binding()
    payload["binding_type"] = "local_capture"
    with pytest.raises(ValidationError):
        _BINDING_ADAPTER.validate_python(payload)


def test_unknown_discriminant_rejected() -> None:
    payload = _provider_binding()
    payload["binding_type"] = "provider_stream"
    with pytest.raises(ValidationError):
        _BINDING_ADAPTER.validate_python(payload)


def test_missing_branch_field_rejected() -> None:
    payload = _provider_binding()
    del payload["provider_task_id"]  # required for provider_task
    with pytest.raises(ValidationError):
        _BINDING_ADAPTER.validate_python(payload)


def test_provider_fields_on_local_branch_rejected() -> None:
    payload = _local_binding()
    payload["provider_task_id"] = "pt1"  # not a local_result field
    with pytest.raises(ValidationError):
        _BINDING_ADAPTER.validate_python(payload)


def test_budget_rejects_overconsumption() -> None:
    with pytest.raises(ValidationError):
        MissionExecutionBudget(
            mission_id="m1", mission_revision=1, budget_version=1, max_dispatch_claims=2,
            consumed_dispatch_claims=3, updated_at=T0, record_digest="rd",
        )
