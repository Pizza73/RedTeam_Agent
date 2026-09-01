"""Repository-backed authorization for encrypted data stores."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Literal, final

from redteam_agent.authorization_runtime import (
    AuthorizationRuntimeContext,
    AuthorizationRuntimeContextResolver,
)
from redteam_agent.errors import SecretAccessError
from redteam_agent.models.common import require_utc
from redteam_agent.models.context import DataAccessGrant, ResourceBinding
from redteam_agent.models.policy import PolicyDecision
from redteam_agent.models.scope import DataAccessOperation, DataResourceType
from redteam_agent.policy.data_access import DataAccessEvaluator
from redteam_agent.repositories import (
    AdapterCapabilitySnapshotRepository,
    AuthorizationRuntimeBindingRepository,
    AvailableToolSnapshotRepository,
    ExecutionRepository,
    MissionRevisionRepository,
    MissionStateRepository,
    PolicyDecisionRepository,
    PolicyStateRepository,
    RemoteMCPTrustSnapshotRepository,
    SandboxCapabilitySnapshotRepository,
    SessionSecurityContextSnapshotRepository,
    ToolRegistryRepository,
)
from redteam_agent.storage import Database


class DataAccessAuthorizer(ABC):
    """Nominal trusted boundary used by encrypted stores.

    Store constructors reject structural lookalikes. Production assembly uses
    ``RepositoryDataAccessAuthorizer``; explicit subclasses remain possible for
    isolated boundary tests.
    """

    @abstractmethod
    def require_access(
        self,
        *,
        mission_id: str,
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
        now: datetime,
    ) -> None: ...


@final
class RepositoryDataAccessAuthorizer(DataAccessAuthorizer):
    """Revalidate immutable grants and execution provenance against current state."""

    _INGESTION_EXECUTION_STATES = frozenset(
        {
            "DISPATCHED",
            "RUNNING",
            "SUCCEEDED",
            "FAILED",
            "CANCEL_REQUESTED",
            "CANCELLED",
            "RECONCILING",
            "OUTCOME_UNKNOWN",
        }
    )

    def __init__(
        self,
        *,
        database: Database,
    ) -> None:
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
        self._evaluator = DataAccessEvaluator()

    def require_access(
        self,
        *,
        mission_id: str,
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
            decision_ids = self._decisions.decision_ids_for_exact_data_access(
                resource
            )
            authorized = False
            for decision_id in decision_ids:
                decision = self._decisions.get(decision_id)
                if decision is None:
                    raise SecretAccessError("persisted data access grant has no decision envelope")
                if not self._decision_is_current(
                    decision,
                    runtime=runtime,
                    now=now,
                    require_direct_allow=True,
                ):
                    continue
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
                if len(matching) > 1:
                    raise SecretAccessError("persisted data access grant is ambiguous")
                authorized = authorized or len(matching) == 1
        except SecretAccessError:
            raise
        except Exception as exc:
            raise SecretAccessError("trusted data access evidence is unavailable") from exc
        if not authorized:
            raise SecretAccessError("no current trusted decision grants the resource operation")

    def require_ingestion_write(
        self,
        *,
        mission_id: str,
        source_execution_id: str,
        resource_type: Literal["artifact", "secret_reference"],
        resource: ResourceBinding,
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
        try:
            execution = self._executions.get(source_execution_id)
            if execution is None:
                raise SecretAccessError("trusted source execution is required for ingestion")
            decision = self._decisions.get(execution.policy_decision_id)
        except SecretAccessError:
            raise
        except Exception as exc:
            raise SecretAccessError(
                "trusted ingestion authorization evidence is unavailable"
            ) from exc
        if decision is None:
            raise SecretAccessError("trusted source execution decision is unavailable")
        if not (
            execution.mission_id == mission_id
            and execution.mission_revision == runtime.mission.mission_revision
            and execution.authorization_epoch == runtime.mission.authorization_epoch
            and execution.authorization_digest == decision.authorization_digest
            and execution.provider_execution_state in self._INGESTION_EXECUTION_STATES
            and self._decision_is_current(
                decision,
                runtime=runtime,
                now=now,
                require_direct_allow=False,
            )
        ):
            raise SecretAccessError("source execution is not current ingestion authority")

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
            raise SecretAccessError("current data access authorization state is invalid") from exc
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
        require_direct_allow: bool,
    ) -> bool:
        mission = runtime.mission
        return (
            (decision.decision == "ALLOW" if require_direct_allow else decision.decision != "DENY")
            and decision.mission_id == mission.mission_id
            and decision.mission_revision == mission.mission_revision
            and decision.authorization_epoch == mission.authorization_epoch
            and decision.policy_version == runtime.policy_state.policy_version
            and decision.registry_digest == runtime.registry.registry_digest
            and decision.available_tool_snapshot_id == runtime.snapshot.snapshot_id
            and decision.available_tool_snapshot_digest == runtime.snapshot.snapshot_digest
            and decision.session_security_context_digest == runtime.session_snapshot.snapshot_digest
            and decision.adapter_capabilities_digest == runtime.adapter_snapshot.snapshot_digest
            and decision.sandbox_capabilities_digest == runtime.sandbox_snapshot.snapshot_digest
            and decision.remote_mcp_trust_policy_digest
            == runtime.remote_trust_snapshot.snapshot_digest
            and decision.issued_at <= now < decision.expires_at
        )
