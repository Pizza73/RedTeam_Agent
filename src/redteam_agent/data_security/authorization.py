"""Repository-backed authorization for encrypted data stores."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Literal, final

from pydantic import Field

from redteam_agent.authorization_runtime import (
    AuthorizationRuntimeContext,
    AuthorizationRuntimeContextResolver,
)
from redteam_agent.canonical import sha256_digest, stable_id
from redteam_agent.errors import SecretAccessError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import require_utc
from redteam_agent.models.context import DataAccessGrant, ResourceBinding
from redteam_agent.models.execution import ExecutionRecord, RawResultReceipt
from redteam_agent.models.policy import PolicyDecision
from redteam_agent.models.scope import DataAccessOperation, DataResourceType
from redteam_agent.policy.data_access import DataAccessEvaluator
from redteam_agent.repositories import (
    AdapterCapabilitySnapshotRepository,
    AuthorizationRuntimeBindingRepository,
    AvailableToolSnapshotRepository,
    ContextResourceIndexRepository,
    ExecutionRepository,
    MissionRevisionRepository,
    MissionStateRepository,
    PolicyDecisionRepository,
    PolicyStateRepository,
    RawResultReceiptRepository,
    RemoteMCPTrustSnapshotRepository,
    ResultIngestionRepository,
    SandboxCapabilitySnapshotRepository,
    SessionSecurityContextSnapshotRepository,
    ToolRegistryRepository,
)
from redteam_agent.storage import Database


class IngestionWriteEvidence(StrictImmutableBoundaryModel):
    """Current lease and receipt binding required for secure-ingestion writes."""

    execution_id: str = Field(min_length=1)
    ingestion_id: str = Field(min_length=1)
    ingestion_digest: str = Field(min_length=1)
    ingestion_state_version: int = Field(ge=0)
    ingestion_attempt: int = Field(ge=1)
    lease_id: str = Field(min_length=1)
    receipt_id: str = Field(min_length=1)
    receipt_digest: str = Field(min_length=1)
    quarantine_id: str = Field(min_length=1)


def ingestion_output_authority(
    *,
    mission_id: str,
    plan_id: str,
    resource_type: Literal["artifact", "secret_reference"],
) -> ResourceBinding:
    """Build the prospective output slot that a PolicyDecision must grant."""

    payload = {
        "schema_version": "secure-ingestion-output-authority-v1",
        "mission_id": mission_id,
        "plan_id": plan_id,
        "resource_type": resource_type,
    }
    return ResourceBinding(
        resource_id=stable_id("ingestionoutput", payload),
        resource_version="1",
        resource_digest=sha256_digest(payload),
    )


class DataAccessAuthorizer(ABC):
    """Nominal trusted boundary used by encrypted stores."""

    @abstractmethod
    def require_access(
        self,
        *,
        mission_id: str,
        execution_id: str,
        resource_type: DataResourceType,
        resource: ResourceBinding,
        operation: DataAccessOperation,
        now: datetime,
    ) -> None: ...

    @abstractmethod
    def require_ingestion_write(
        self,
        *,
        mission_id: str,
        source_execution_id: str,
        resource_type: Literal["artifact", "secret_reference"],
        resource: ResourceBinding,
        evidence: IngestionWriteEvidence | None,
        now: datetime,
    ) -> None: ...

    @abstractmethod
    def current_ingestion_evidence(
        self,
        *,
        receipt: RawResultReceipt,
        now: datetime,
    ) -> IngestionWriteEvidence: ...


@final
class RepositoryDataAccessAuthorizer(DataAccessAuthorizer):
    """Revalidate immutable grants and execution provenance against current state."""

    _POST_DISPATCH_STATES = (
        "DISPATCHED",
        "RUNNING",
        "SUCCEEDED",
        "FAILED",
        "CANCEL_REQUESTED",
        "CANCELLED",
        "RECONCILING",
        "OUTCOME_UNKNOWN",
    )

    def __init__(self, *, database: Database) -> None:
        self._runtime_resolver = AuthorizationRuntimeContextResolver(
            revisions=MissionRevisionRepository(database),
            states=MissionStateRepository(database),
            policies=PolicyStateRepository(database),
            bindings=AuthorizationRuntimeBindingRepository(database),
            registries=ToolRegistryRepository(database),
            available_snapshots=AvailableToolSnapshotRepository(database),
            sessions=SessionSecurityContextSnapshotRepository(database),
            adapters=AdapterCapabilitySnapshotRepository(database),
            sandboxes=SandboxCapabilitySnapshotRepository(database),
            remote_trust=RemoteMCPTrustSnapshotRepository(database),
        )
        self._decisions = PolicyDecisionRepository(database)
        self._executions = ExecutionRepository(database)
        self._resources = ContextResourceIndexRepository(database)
        self._ingestions = ResultIngestionRepository(database)
        self._receipts = RawResultReceiptRepository(database)
        self._evaluator = DataAccessEvaluator()

    def require_access(
        self,
        *,
        mission_id: str,
        execution_id: str,
        resource_type: DataResourceType,
        resource: ResourceBinding,
        operation: DataAccessOperation,
        now: datetime,
    ) -> None:
        runtime = self._current_runtime(mission_id=mission_id, now=now)
        requested = DataAccessGrant(
            resource_type=resource_type,
            resource=resource,
            operations=frozenset({operation}),
        )
        if not self._evaluator.allows(requested, runtime.mission.data_access_policy):
            raise SecretAccessError("current data access policy denies the resource")
        try:
            _, decision = self._current_execution_decision(
                execution_id=execution_id,
                runtime=runtime,
                now=now,
                allowed_states=("AUTHORIZED", *self._POST_DISPATCH_STATES),
            )
            current = self._resources.current_binding(
                mission_id,
                resource.resource_id,
            )
            matching = tuple(
                grant
                for grant in decision.authorized_data_access
                if grant.resource_type == resource_type
                and grant.resource == resource
                and operation in grant.operations
                and self._evaluator.allows(
                    grant,
                    runtime.mission.data_access_policy,
                )
            )
        except SecretAccessError:
            raise
        except Exception as exc:
            raise SecretAccessError(
                "trusted execution data access evidence is unavailable"
            ) from exc
        if not (
            len(matching) == 1
            and current is not None
            and current.resource_type == resource_type
            and current.binding == resource
            and current.verification_state == "confirmed"
        ):
            raise SecretAccessError(
                "execution does not hold the current exact resource grant"
            )

    def require_ingestion_write(
        self,
        *,
        mission_id: str,
        source_execution_id: str,
        resource_type: Literal["artifact", "secret_reference"],
        resource: ResourceBinding,
        evidence: IngestionWriteEvidence | None,
        now: datetime,
    ) -> None:
        runtime = self._current_runtime(mission_id=mission_id, now=now)
        requested = DataAccessGrant(
            resource_type=resource_type,
            resource=resource,
            operations=frozenset({"write"}),
        )
        if not self._evaluator.allows(requested, runtime.mission.data_access_policy):
            raise SecretAccessError("current data access policy denies ingestion output")
        if evidence is None:
            raise SecretAccessError(
                "current result-ingestion evidence is required for writes"
            )
        try:
            execution, decision = self._current_execution_decision(
                execution_id=source_execution_id,
                runtime=runtime,
                now=now,
                allowed_states=self._POST_DISPATCH_STATES,
            )
            verified_evidence = self._current_ingestion_evidence(
                execution=execution,
                now=now,
            )
            authority = ingestion_output_authority(
                mission_id=mission_id,
                plan_id=execution.plan_id,
                resource_type=resource_type,
            )
            current_authority = self._resources.current_binding(
                mission_id,
                authority.resource_id,
            )
            matching = tuple(
                grant
                for grant in decision.authorized_data_access
                if grant.resource_type == resource_type
                and grant.resource == authority
                and "write" in grant.operations
                and self._evaluator.allows(
                    grant,
                    runtime.mission.data_access_policy,
                )
            )
        except SecretAccessError:
            raise
        except Exception as exc:
            raise SecretAccessError(
                "trusted ingestion authorization evidence is unavailable"
            ) from exc
        if not (
            evidence == verified_evidence
            and execution.result_ingestion_state == "INGESTING"
            and len(matching) == 1
            and current_authority is not None
            and current_authority.resource_type == resource_type
            and current_authority.binding == authority
            and current_authority.verification_state == "confirmed"
        ):
            raise SecretAccessError(
                "write is not bound to current ingestion output authority"
            )

    def current_ingestion_evidence(
        self,
        *,
        receipt: RawResultReceipt,
        now: datetime,
    ) -> IngestionWriteEvidence:
        try:
            require_utc(now)
            execution = self._executions.get(receipt.execution_id)
            persisted_receipt = self._receipts.get(receipt.receipt_id)
            if execution is None or persisted_receipt != receipt:
                raise SecretAccessError("trusted ingestion receipt is unavailable")
            evidence = self._current_ingestion_evidence(
                execution=execution,
                now=now,
            )
            if not (
                evidence.receipt_id == receipt.receipt_id
                and evidence.receipt_digest == receipt.receipt_digest
                and evidence.quarantine_id == receipt.quarantine_id
            ):
                raise SecretAccessError(
                    "receipt is not bound to the current result ingestion"
                )
            return evidence
        except SecretAccessError:
            raise
        except Exception as exc:
            raise SecretAccessError(
                "trusted ingestion evidence is unavailable"
            ) from exc

    def _current_ingestion_evidence(
        self,
        *,
        execution: ExecutionRecord,
        now: datetime,
    ) -> IngestionWriteEvidence:
        ingestion = self._ingestions.get_by_execution(execution.execution_id)
        if (
            ingestion is None
            or ingestion.status != "INGESTING"
            or execution.result_ingestion_state != "INGESTING"
            or ingestion.receipt_id is None
            or ingestion.quarantine_id is None
            or ingestion.lease_id is None
            or ingestion.lease_expires_at is None
            or now >= ingestion.lease_expires_at
        ):
            raise SecretAccessError("result ingestion is not actively leased")
        receipt = self._receipts.get(ingestion.receipt_id)
        if receipt is None or not (
            receipt.execution_id == execution.execution_id
            and receipt.quarantine_id == ingestion.quarantine_id
        ):
            raise SecretAccessError("result-ingestion receipt binding is invalid")
        return IngestionWriteEvidence(
            execution_id=execution.execution_id,
            ingestion_id=ingestion.ingestion_id,
            ingestion_digest=ingestion.ingestion_digest,
            ingestion_state_version=ingestion.state_version,
            ingestion_attempt=ingestion.attempt_count,
            lease_id=ingestion.lease_id,
            receipt_id=receipt.receipt_id,
            receipt_digest=receipt.receipt_digest,
            quarantine_id=receipt.quarantine_id,
        )

    def _current_execution_decision(
        self,
        *,
        execution_id: str,
        runtime: AuthorizationRuntimeContext,
        now: datetime,
        allowed_states: tuple[str, ...],
    ) -> tuple[ExecutionRecord, PolicyDecision]:
        execution = self._executions.get(execution_id)
        if execution is None:
            raise SecretAccessError("trusted execution is required")
        decision = self._decisions.get(execution.policy_decision_id)
        if decision is None or not (
            execution.mission_id == runtime.mission.mission_id
            and execution.mission_revision == runtime.mission.mission_revision
            and execution.authorization_epoch == runtime.mission.authorization_epoch
            and execution.authorization_digest == decision.authorization_digest
            and execution.provider_execution_state in allowed_states
            and self._decision_is_current(
                decision,
                runtime=runtime,
                now=now,
            )
        ):
            raise SecretAccessError("execution authorization is stale or denied")
        return execution, decision

    def _current_runtime(
        self,
        *,
        mission_id: str,
        now: datetime,
    ) -> AuthorizationRuntimeContext:
        try:
            require_utc(now)
            runtime = self._runtime_resolver.resolve(mission_id)
        except Exception as exc:
            raise SecretAccessError(
                "current data access authorization state is invalid"
            ) from exc
        mission = runtime.mission
        if not (
            mission.state == "RUNNING"
            and mission.valid_from <= now < mission.valid_until
            and runtime.snapshot.created_at <= now < runtime.snapshot.expires_at
        ):
            raise SecretAccessError("current data access authorization state is stale")
        return runtime

    @staticmethod
    def _decision_is_current(
        decision: PolicyDecision,
        *,
        runtime: AuthorizationRuntimeContext,
        now: datetime,
    ) -> bool:
        mission = runtime.mission
        return (
            decision.decision != "DENY"
            and decision.mission_id == mission.mission_id
            and decision.mission_revision == mission.mission_revision
            and decision.authorization_epoch == mission.authorization_epoch
            and decision.policy_version == runtime.policy_state.policy_version
            and decision.registry_digest == runtime.registry.registry_digest
            and decision.available_tool_snapshot_id == runtime.snapshot.snapshot_id
            and decision.available_tool_snapshot_digest
            == runtime.snapshot.snapshot_digest
            and decision.session_security_context_digest
            == runtime.session_snapshot.snapshot_digest
            and decision.adapter_capabilities_digest
            == runtime.adapter_snapshot.snapshot_digest
            and decision.sandbox_capabilities_digest
            == runtime.sandbox_snapshot.snapshot_digest
            and decision.remote_mcp_trust_policy_digest
            == runtime.remote_trust_snapshot.snapshot_digest
            and decision.issued_at <= now < decision.expires_at
        )
