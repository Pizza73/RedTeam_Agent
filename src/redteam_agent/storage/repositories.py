"""Typed SQLite repositories with write/read integrity (SystemDesign §32).

Guarantees enforced here:

* Write integrity: every model is re-validated through its strict schema before
  storage (a ``model_construct`` bypass cannot be persisted) and its digest /
  id-binding is verified (B-06 / H-03).
* Read integrity: every read (single and bulk) goes through the
  duplicate-key-rejecting boundary loader, verifies the digest / id binding, and
  compares the *actual* stored row key against the payload identity, so a
  swapped row key or a mismatched nested id fails closed (Codex #4).
* Owner-only writes: authorization artifacts (mission state, lifecycle event,
  policy decision, snapshot, approval request/record, context grant) can only be
  persisted with the composition-issued write guard held by their owner service.
  A caller holding a repository reference cannot raw-save a forged artifact
  (Codex #1 / #2).
* Mission state transitions are validated (expected version/epoch/state + legal
  edge) and must run inside an active unit of work.
"""

from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel, ValidationError

from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.approval.models import ApprovalRecord, ApprovalRequest
from redteam_agent.auth.models import MissionRoleAssignment
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.json_boundary import load_model_from_json
from redteam_agent.context.models import ContextDataAccessGrant, ContextResourceIndexRecord
from redteam_agent.contracts.catalog import ActionContractCatalog, RuleCatalog
from redteam_agent.errors import (
    MissionLifecycleError,
    MissionStateVersionConflictError,
    RepositoryIntegrityError,
)
from redteam_agent.llm.profile import AgentModelProfile
from redteam_agent.mission.models import (
    EPOCH_ROTATING_EDGES,
    LEGAL_LIFECYCLE_EDGES,
    MissionLifecycleEvent,
    MissionLifecycleState,
    MissionRevision,
    MissionState,
)
from redteam_agent.policy.models import PolicyDecision
from redteam_agent.policy.risk_policy import EffectiveRiskPolicy
from redteam_agent.sandbox.models import SandboxCapabilities
from redteam_agent.session.models import SessionSecurityContextSnapshot
from redteam_agent.storage.database import Database
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.integrity import verify_object_integrity
from redteam_agent.tools.availability import AvailableToolSnapshot
from redteam_agent.tools.registry import ToolRegistryRevision, validate_tool_registry
from redteam_agent.tools.target_extractors import TrustedTargetExtractorRegistry

_M = TypeVar("_M", bound=BaseModel)


class _BaseRepository:
    def __init__(self, database: Database, digest_service: DigestService) -> None:
        self._db = database
        self._digests = digest_service

    def _dump(self, model: BaseModel) -> str:
        # Validate through the strict schema *before* serializing, so a model
        # built via ``model_construct`` (bypassing validation) is rejected with a
        # content-free error and never reaches the serializer (which would emit a
        # warning echoing the offending value). The exception chain is dropped so
        # no input value leaks into a traceback (Codex #B / G).
        try:
            validated = type(model).model_validate(dict(model))
        except ValidationError:
            raise RepositoryIntegrityError("model failed strict schema validation before storage") from None
        verify_object_integrity(validated, self._digests)  # write-side integrity
        return validated.model_dump_json()

    def _load(self, model_cls: type[_M], json_text: str, *, row_key: str, payload_key: str) -> _M:
        model = load_model_from_json(model_cls, json_text)  # dup-key reject + strict
        verify_object_integrity(model, self._digests)  # read-side integrity
        if row_key != payload_key:
            raise RepositoryIntegrityError("stored row key does not match payload identity")
        return model


class _GuardedRepository(_BaseRepository):
    def __init__(self, database: Database, digest_service: DigestService) -> None:
        super().__init__(database, digest_service)
        self._owner: WriteGuard | None = None

    def bind_owner(self, guard: WriteGuard) -> None:
        if self._owner is not None:
            raise RepositoryIntegrityError("repository owner already bound")
        self._owner = guard

    def _authorize_write(self, guard: WriteGuard, *, require_transaction: bool = False) -> None:
        if self._owner is None or guard is not self._owner:
            raise RepositoryIntegrityError("unauthorized repository write (missing owner guard)")
        if require_transaction and not self._db.in_transaction:
            raise RepositoryIntegrityError("write requires an active unit of work")


class MissionRevisionRepository(_BaseRepository):
    _NS = "mission_revisions"

    def save(self, revision: MissionRevision) -> None:
        key = f"{revision.mission_id}/{revision.mission_revision}"
        self._db.put_idempotent(self._NS, key, self._dump(revision))

    def get(self, mission_id: str, mission_revision: int) -> MissionRevision | None:
        key = f"{mission_id}/{mission_revision}"
        raw = self._db.get(self._NS, key)
        if raw is None:
            return None
        model = load_model_from_json(MissionRevision, raw)
        payload_key = f"{model.mission_id}/{model.mission_revision}"
        return self._load(MissionRevision, raw, row_key=key, payload_key=payload_key)


class MissionStateRepository(_GuardedRepository):
    _NS = "mission_states"

    def get(self, mission_id: str) -> MissionState | None:
        raw = self._db.get(self._NS, mission_id)
        if raw is None:
            return None
        model = load_model_from_json(MissionState, raw)
        return self._load(MissionState, raw, row_key=mission_id, payload_key=model.mission_id)

    def create(self, state: MissionState, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        if state.mission_state_version != 0 or state.state != "DRAFT":
            raise MissionLifecycleError("initial mission state must be DRAFT at version 0")
        if self.get(state.mission_id) is not None:
            raise MissionLifecycleError("mission already exists")
        self._db.put_idempotent(self._NS, state.mission_id, self._dump(state))

    def apply_transition(
        self,
        *,
        guard: WriteGuard,
        mission_id: str,
        expected_version: int,
        expected_epoch: int,
        expected_state: MissionLifecycleState,
        target_state: MissionLifecycleState,
    ) -> MissionState:
        self._authorize_write(guard, require_transaction=True)
        current = self.get(mission_id)
        if current is None:
            raise MissionLifecycleError("mission does not exist")
        if current.mission_state_version != expected_version:
            raise MissionStateVersionConflictError(
                f"expected version {expected_version}, current {current.mission_state_version}"
            )
        if current.authorization_epoch != expected_epoch:
            raise MissionStateVersionConflictError("authorization epoch conflict")
        if current.state != expected_state:
            raise MissionStateVersionConflictError("unexpected current state")
        if (current.state, target_state) not in LEGAL_LIFECYCLE_EDGES:
            raise MissionLifecycleError(f"illegal transition {current.state} -> {target_state}")
        rotate = (current.state, target_state) in EPOCH_ROTATING_EDGES
        new_state = MissionState(
            mission_id=mission_id,
            mission_revision=current.mission_revision,
            mission_state_version=current.mission_state_version + 1,
            authorization_epoch=current.authorization_epoch + (1 if rotate else 0),
            state=target_state,
        )
        self._db.overwrite(self._NS, mission_id, self._dump(new_state))
        return new_state

    def rotate_epoch_in_place(
        self, *, guard: WriteGuard, mission_id: str, expected_version: int, expected_epoch: int
    ) -> MissionState:
        self._authorize_write(guard, require_transaction=True)
        current = self.get(mission_id)
        if current is None:
            raise MissionLifecycleError("mission does not exist")
        if current.mission_state_version != expected_version or current.authorization_epoch != expected_epoch:
            raise MissionStateVersionConflictError("mission state/epoch conflict")
        if current.state not in ("RUNNING", "PAUSED"):
            raise MissionLifecycleError("authorization can only be invalidated while RUNNING or PAUSED")
        new_state = MissionState(
            mission_id=mission_id,
            mission_revision=current.mission_revision,
            mission_state_version=current.mission_state_version + 1,
            authorization_epoch=current.authorization_epoch + 1,
            state=current.state,
        )
        self._db.overwrite(self._NS, mission_id, self._dump(new_state))
        return new_state


class MissionLifecycleEventRepository(_GuardedRepository):
    _NS = "mission_lifecycle_events"

    def append(self, event: MissionLifecycleEvent, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        key = f"{event.mission_id}/{event.sequence_number}"
        self._db.put_idempotent(self._NS, key, self._dump(event))

    def next_sequence(self, mission_id: str) -> int:
        highest = 0
        for row_key, raw in self._db.get_all(self._NS):
            payload_key = f"{_event_mid(raw)}/{_event_seq(raw)}"
            event = self._load(MissionLifecycleEvent, raw, row_key=row_key, payload_key=payload_key)
            if event.mission_id == mission_id:
                highest = max(highest, event.sequence_number)
        return highest + 1

    def events_for(self, mission_id: str) -> tuple[MissionLifecycleEvent, ...]:
        events = []
        for row_key, raw in self._db.get_all(self._NS):
            payload_key = f"{_event_mid(raw)}/{_event_seq(raw)}"
            event = self._load(MissionLifecycleEvent, raw, row_key=row_key, payload_key=payload_key)
            if event.mission_id == mission_id:
                events.append(event)
        return tuple(sorted(events, key=lambda e: e.sequence_number))


class ToolRegistryRepository(_BaseRepository):
    _NS = "tool_registry_revisions"

    def __init__(
        self,
        database: Database,
        digest_service: DigestService,
        *,
        contract_catalog: ActionContractCatalog,
        rule_catalog: RuleCatalog,
        extractors: TrustedTargetExtractorRegistry | None = None,
    ) -> None:
        super().__init__(database, digest_service)
        self._contract_catalog = contract_catalog
        self._rule_catalog = rule_catalog
        self._extractors = extractors

    def _validate(self, registry: ToolRegistryRevision) -> None:
        validate_tool_registry(
            registry,
            digest_service=self._digests,
            contract_catalog=self._contract_catalog,
            rule_catalog=self._rule_catalog,
            extractors=self._extractors,
        )

    def save(self, registry: ToolRegistryRevision) -> None:
        # Re-run full domain validation so a self-consistent but invalid registry
        # cannot be registered via the raw repository path (R13).
        self._validate(registry)
        self._db.put_idempotent(self._NS, str(registry.registry_revision), self._dump(registry))

    def get(self, registry_revision: int) -> ToolRegistryRevision | None:
        key = str(registry_revision)
        raw = self._db.get(self._NS, key)
        if raw is None:
            return None
        model = load_model_from_json(ToolRegistryRevision, raw)
        registry = self._load(ToolRegistryRevision, raw, row_key=key, payload_key=str(model.registry_revision))
        self._validate(registry)
        return registry


class PolicyRevisionRepository(_BaseRepository):
    _NS = "policy_revisions"

    def save(self, policy: EffectiveRiskPolicy) -> None:
        self._db.put_idempotent(self._NS, policy.policy_version, self._dump(policy))

    def get(self, policy_version: str) -> EffectiveRiskPolicy | None:
        raw = self._db.get(self._NS, policy_version)
        if raw is None:
            return None
        model = load_model_from_json(EffectiveRiskPolicy, raw)
        return self._load(EffectiveRiskPolicy, raw, row_key=policy_version, payload_key=model.policy_version)


class AvailableToolSnapshotRepository(_GuardedRepository):
    _NS = "available_tool_snapshots"

    def save(self, snapshot: AvailableToolSnapshot, *, guard: WriteGuard) -> None:
        self._authorize_write(guard)
        self._db.put_idempotent(self._NS, snapshot.snapshot_id, self._dump(snapshot))

    def get(self, snapshot_id: str) -> AvailableToolSnapshot | None:
        raw = self._db.get(self._NS, snapshot_id)
        if raw is None:
            return None
        model = load_model_from_json(AvailableToolSnapshot, raw)
        return self._load(AvailableToolSnapshot, raw, row_key=snapshot_id, payload_key=model.snapshot_id)


class PolicyDecisionRepository(_GuardedRepository):
    _NS = "policy_decisions"

    def save(self, decision: PolicyDecision, *, guard: WriteGuard) -> None:
        self._authorize_write(guard)
        self._db.put_idempotent(self._NS, decision.decision_id, self._dump(decision))

    def get(self, decision_id: str) -> PolicyDecision | None:
        raw = self._db.get(self._NS, decision_id)
        if raw is None:
            return None
        model = load_model_from_json(PolicyDecision, raw)
        return self._load(PolicyDecision, raw, row_key=decision_id, payload_key=model.decision_id)


class ApprovalRequestRepository(_GuardedRepository):
    _NS = "approval_requests"

    def save(self, request: ApprovalRequest, *, guard: WriteGuard) -> None:
        self._authorize_write(guard)
        self._db.put_idempotent(self._NS, request.approval_request_id, self._dump(request))

    def get(self, approval_request_id: str) -> ApprovalRequest | None:
        raw = self._db.get(self._NS, approval_request_id)
        if raw is None:
            return None
        model = load_model_from_json(ApprovalRequest, raw)
        return self._load(ApprovalRequest, raw, row_key=approval_request_id, payload_key=model.approval_request_id)

    def find_by_decision(self, decision_id: str) -> ApprovalRequest | None:
        for row_key, raw in self._db.get_all(self._NS):
            model = load_model_from_json(ApprovalRequest, raw)
            request = self._load(ApprovalRequest, raw, row_key=row_key, payload_key=model.approval_request_id)
            if request.policy_decision_id == decision_id:
                return request
        return None


class ApprovalRecordRepository(_GuardedRepository):
    _NS = "approvals"

    def save(self, record: ApprovalRecord, *, guard: WriteGuard) -> None:
        self._authorize_write(guard)
        self._db.put_idempotent(self._NS, record.approval_id, self._dump(record))

    def get(self, approval_id: str) -> ApprovalRecord | None:
        raw = self._db.get(self._NS, approval_id)
        if raw is None:
            return None
        model = load_model_from_json(ApprovalRecord, raw)
        return self._load(ApprovalRecord, raw, row_key=approval_id, payload_key=model.approval_id)

    def find_by_request(self, approval_request_id: str) -> ApprovalRecord | None:
        for row_key, raw in self._db.get_all(self._NS):
            model = load_model_from_json(ApprovalRecord, raw)
            record = self._load(ApprovalRecord, raw, row_key=row_key, payload_key=model.approval_id)
            if record.approval_request_id == approval_request_id:
                return record
        return None


class ContextDataAccessGrantRepository(_GuardedRepository):
    _NS = "context_data_access_grants"

    def save(self, grant: ContextDataAccessGrant, *, guard: WriteGuard) -> None:
        self._authorize_write(guard)
        self._db.put_idempotent(self._NS, grant.grant_id, self._dump(grant))

    def get(self, grant_id: str) -> ContextDataAccessGrant | None:
        raw = self._db.get(self._NS, grant_id)
        if raw is None:
            return None
        model = load_model_from_json(ContextDataAccessGrant, raw)
        return self._load(ContextDataAccessGrant, raw, row_key=grant_id, payload_key=model.grant_id)


class AgentProfileRepository(_BaseRepository):
    _NS = "llm_profiles"

    def save(self, profile: AgentModelProfile) -> None:
        self._db.put_idempotent(self._NS, profile.profile_revision, self._dump(profile))

    def get(self, profile_revision: str) -> AgentModelProfile | None:
        raw = self._db.get(self._NS, profile_revision)
        if raw is None:
            return None
        model = load_model_from_json(AgentModelProfile, raw)
        return self._load(AgentModelProfile, raw, row_key=profile_revision, payload_key=model.profile_revision)


class SessionSecurityContextSnapshotRepository(_BaseRepository):
    _NS = "session_security_context_snapshots"

    def save(self, snapshot: SessionSecurityContextSnapshot) -> None:
        # Session runtime state is refreshed by the trusted Session Manager.
        self._db.overwrite(self._NS, snapshot.session_id, self._dump(snapshot))

    def get(self, session_id: str) -> SessionSecurityContextSnapshot | None:
        raw = self._db.get(self._NS, session_id)
        if raw is None:
            return None
        model = load_model_from_json(SessionSecurityContextSnapshot, raw)
        return self._load(SessionSecurityContextSnapshot, raw, row_key=session_id, payload_key=model.session_id)

    def all_snapshots(self) -> dict[str, SessionSecurityContextSnapshot]:
        result: dict[str, SessionSecurityContextSnapshot] = {}
        for row_key, raw in self._db.get_all(self._NS):
            model = load_model_from_json(SessionSecurityContextSnapshot, raw)
            result[row_key] = self._load(
                SessionSecurityContextSnapshot, raw, row_key=row_key, payload_key=model.session_id
            )
        return result


class AdapterCapabilityRepository(_BaseRepository):
    _NS = "adapter_capability_snapshots"

    def save(self, capabilities: AdapterCapabilities) -> None:
        self._db.put_idempotent(self._NS, capabilities.adapter_id, self._dump(capabilities))

    def get(self, adapter_id: str) -> AdapterCapabilities | None:
        raw = self._db.get(self._NS, adapter_id)
        if raw is None:
            return None
        model = load_model_from_json(AdapterCapabilities, raw)
        return self._load(AdapterCapabilities, raw, row_key=adapter_id, payload_key=model.adapter_id)

    def all_capabilities(self) -> dict[str, AdapterCapabilities]:
        result: dict[str, AdapterCapabilities] = {}
        for row_key, raw in self._db.get_all(self._NS):
            model = load_model_from_json(AdapterCapabilities, raw)
            result[row_key] = self._load(AdapterCapabilities, raw, row_key=row_key, payload_key=model.adapter_id)
        return result


class SandboxCapabilityRepository(_BaseRepository):
    _NS = "sandbox_capability_snapshots"

    def save(self, capabilities: SandboxCapabilities) -> None:
        # Keyed by the bound adapter/runtime so one adapter's sandbox cannot be
        # reused for another (H-04).
        self._db.put_idempotent(self._NS, capabilities.adapter_id, self._dump(capabilities))

    def get(self, adapter_id: str) -> SandboxCapabilities | None:
        raw = self._db.get(self._NS, adapter_id)
        if raw is None:
            return None
        model = load_model_from_json(SandboxCapabilities, raw)
        return self._load(SandboxCapabilities, raw, row_key=adapter_id, payload_key=model.adapter_id)

    def all_capabilities(self) -> dict[str, SandboxCapabilities]:
        result: dict[str, SandboxCapabilities] = {}
        for row_key, raw in self._db.get_all(self._NS):
            model = load_model_from_json(SandboxCapabilities, raw)
            result[row_key] = self._load(SandboxCapabilities, raw, row_key=row_key, payload_key=model.adapter_id)
        return result


class ContextResourceIndexRepository(_BaseRepository):
    _NS = "context_resource_index"

    def save(self, record: ContextResourceIndexRecord) -> None:
        self._db.put_idempotent(self._NS, record.resource_id, self._dump(record))

    def query_by_mission(self, mission_id: str) -> tuple[ContextResourceIndexRecord, ...]:
        records = []
        for row_key, raw in self._db.get_all(self._NS):
            model = load_model_from_json(ContextResourceIndexRecord, raw)
            records.append(self._load(ContextResourceIndexRecord, raw, row_key=row_key, payload_key=model.resource_id))
        return tuple(record for record in records if record.mission_id == mission_id)


class MissionRoleAssignmentRepository(_BaseRepository):
    _NS = "mission_role_assignments"

    def save(self, assignment: MissionRoleAssignment) -> None:
        # Operator/admin RBAC provisioning may update (e.g. revoke) an assignment.
        key = f"{assignment.mission_id}/{assignment.principal_id}/{assignment.role}"
        self._db.overwrite(self._NS, key, self._dump(assignment))

    def assignments_for(self, mission_id: str) -> tuple[MissionRoleAssignment, ...]:
        result = []
        for row_key, raw in self._db.get_all(self._NS):
            model = load_model_from_json(MissionRoleAssignment, raw)
            payload_key = f"{model.mission_id}/{model.principal_id}/{model.role}"
            assignment = self._load(MissionRoleAssignment, raw, row_key=row_key, payload_key=payload_key)
            if assignment.mission_id == mission_id:
                result.append(assignment)
        return tuple(result)


def _event_mid(raw: str) -> str:
    return MissionLifecycleEvent.model_validate_json(raw).mission_id


def _event_seq(raw: str) -> int:
    return MissionLifecycleEvent.model_validate_json(raw).sequence_number
