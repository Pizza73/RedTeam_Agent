"""Explicit, one-time offline trust recovery (SystemDesign §34.2.2).

Recovery is deliberately separate from normal startup.  A trusted administrator
stores an immutable approval binding old/new trust identities and exact adopted
content.  With all workers independently verified stopped, the workflow provisions
fresh generation-0 witnesses, initializes the new deployment counter, invalidates old
leases, replaces the epoch mirror and records one consumed approval plus an audit
discontinuity digest.  Replays reconcile those exact outputs and never re-seed from
unapproved local state.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from typing import Protocol

from redteam_agent.audit.generation import AuthenticatedGenerationCoordinator
from redteam_agent.audit.models import (
    GenerationNamespace,
    NvRole,
    RecoveryNamespaceAdoption,
    TrustRecoveryApproval,
    TrustRecoveryConsumption,
)
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import TrustRecoveryError
from redteam_agent.leases.models import DeploymentEpochMirror
from redteam_agent.leases.service import DeploymentEpochService, LeaseService
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.unit_of_work import (
    ApplicationUnitOfWork,
    FaultInjector,
    NoFaultInjector,
    compute_input_digest,
)

_APPROVAL_NS = "trust_recovery_approval"
_CONSUMPTION_NS = "trust_recovery_consumption"
_ROLES: tuple[NvRole, NvRole, NvRole] = ("audit_head", "wrapped_key_state", "deployment_epoch")
_NAMESPACES: tuple[GenerationNamespace, GenerationNamespace] = ("audit_head", "wrapped_key_state")


class WorkerStopVerifier(Protocol):
    def verify_all_workers_stopped(self) -> str: ...


class AuthorizationInvalidator(Protocol):
    def invalidate_all_authorizations_for_trust_recovery_in_txn(
        self, *, guard: WriteGuard, new_trust_epoch: int
    ) -> tuple[int, str]: ...

    def current_authorizations_for_trust_recovery(
        self, *, new_trust_epoch: int
    ) -> tuple[int, str]: ...


class StaticWorkerStopVerifier:
    """Test/offline adapter for a previously measured worker-stop evidence digest."""

    def __init__(self, evidence_digest: str) -> None:
        self._evidence_digest = evidence_digest

    def verify_all_workers_stopped(self) -> str:
        return self._evidence_digest


def _content_digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _blob_id(namespace: GenerationNamespace, content: str) -> str:
    digest = hashlib.sha256(f"gen-blob-v1\x00{content}".encode()).hexdigest()
    return f"blob-{namespace}-{digest}"


class OfflineTrustRecoveryService:
    def __init__(
        self,
        *,
        database: Database,
        digest_service: DigestService,
        clock: Clock,
        recovery_guard: WriteGuard,
        epoch_service: DeploymentEpochService,
        lease_service: LeaseService,
        worker_stop_verifier: WorkerStopVerifier,
        authorization_invalidator: AuthorizationInvalidator,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._clock = clock
        self._guard = recovery_guard
        self._epoch = epoch_service
        self._leases = lease_service
        self._workers = worker_stop_verifier
        self._authorizations = authorization_invalidator
        self._fault = fault_injector if fault_injector is not None else NoFaultInjector()

    def store_approval(self, *, guard: WriteGuard, approval: TrustRecoveryApproval) -> None:
        """Persist an externally authorized approval; this is not a normal runtime API."""
        if guard is not self._guard:
            raise TrustRecoveryError("trust recovery approval requires the offline recovery guard")
        self._verify_approval_digest(approval)
        with ApplicationUnitOfWork(
            self._db,
            aggregate_name="TrustRecoveryAggregate",
            operation_id=f"store-{approval.approval_id}",
            input_digest=compute_input_digest(approval.model_dump(mode="python")),
        ) as uow:
            if not uow.already_applied:
                self._db.occ_insert_idempotent(
                    _APPROVAL_NS,
                    approval.approval_id,
                    1,
                    json.dumps(approval.model_dump(mode="json"), sort_keys=True),
                )
                uow.record_result(approval.approval_digest)

    def build_approval(
        self,
        *,
        guard: WriteGuard,
        approval_id: str,
        old_trust_epoch: int,
        new_trust_epoch: int,
        old_nv_identity_digests: tuple[str, str, str],
        new_nv_identity_digests: tuple[str, str, str],
        last_verified: Mapping[GenerationNamespace, tuple[str, str]],
        adopted: Mapping[GenerationNamespace, tuple[str, str]],
        worker_stop_evidence_digest: str,
        adoption_reason: str,
        approver_id: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> TrustRecoveryApproval:
        adoptions = tuple(
            RecoveryNamespaceAdoption(
                namespace=namespace,
                last_verified_record_digest=last_verified[namespace][0],
                last_verified_witness_digest=last_verified[namespace][1],
                adopted_state_digest=adopted[namespace][0],
                adopted_blob_id=_blob_id(namespace, adopted[namespace][1]),
                adopted_content_digest=_content_digest(adopted[namespace][1]),
            )
            for namespace in _NAMESPACES
        )
        fields = {
            "approval_id": approval_id,
            "old_trust_epoch": old_trust_epoch,
            "new_trust_epoch": new_trust_epoch,
            "old_nv_identity_digests": old_nv_identity_digests,
            "new_nv_identity_digests": new_nv_identity_digests,
            "adoptions": tuple(item.model_dump(mode="python") for item in adoptions),
            "worker_stop_evidence_digest": worker_stop_evidence_digest,
            "adoption_reason": adoption_reason,
            "approver_id": approver_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        approval = TrustRecoveryApproval(
            **{**fields, "adoptions": adoptions},  # type: ignore[arg-type]
            approval_digest=self._ds.compute("trust_recovery_approval_digest", fields),
        )
        self.store_approval(guard=guard, approval=approval)
        return approval

    def _load_approval(self, approval_id: str) -> TrustRecoveryApproval:
        row = self._db.occ_get(_APPROVAL_NS, approval_id)
        if row is None:
            raise TrustRecoveryError("trust recovery approval is missing")
        approval = TrustRecoveryApproval.model_validate_json(row[1])
        self._verify_approval_digest(approval)
        return approval

    def _verify_approval_digest(self, approval: TrustRecoveryApproval) -> None:
        payload = approval.model_dump(mode="python")
        self._ds.verify(
            "trust_recovery_approval_digest",
            {k: v for k, v in payload.items() if k != "approval_digest"},
            approval.approval_digest,
        )

    def _existing_consumption(self, approval: TrustRecoveryApproval) -> TrustRecoveryConsumption | None:
        row = self._db.occ_get(_CONSUMPTION_NS, approval.approval_id)
        if row is None:
            return None
        consumed = TrustRecoveryConsumption.model_validate_json(row[1])
        payload = consumed.model_dump(mode="python")
        self._ds.verify(
            "trust_recovery_consumption_digest",
            {k: v for k, v in payload.items() if k != "consumption_digest"},
            consumed.consumption_digest,
        )
        if consumed.approval_digest != approval.approval_digest:
            raise TrustRecoveryError("recovery consumption is bound to another approval")
        return consumed

    def recover(
        self,
        *,
        approval_id: str,
        new_coordinator: AuthenticatedGenerationCoordinator,
        adopted_contents: Mapping[GenerationNamespace, str],
        provider_identity: str,
    ) -> TrustRecoveryConsumption:
        approval = self._load_approval(approval_id)
        existing = self._existing_consumption(approval)
        now = self._clock.now()
        if existing is None and (now < approval.issued_at or now >= approval.expires_at):
            raise TrustRecoveryError("trust recovery approval is not currently valid")
        stopped = self._workers.verify_all_workers_stopped()
        if stopped != approval.worker_stop_evidence_digest:
            raise TrustRecoveryError("worker-stop evidence does not match the approval")
        old_mirror = self._epoch.current()
        if existing is None and (
            old_mirror is None
            or old_mirror.trust_epoch != approval.old_trust_epoch
            or old_mirror.nv_identity_digest != approval.old_nv_identity_digests[2]
        ):
            raise TrustRecoveryError("old trust epoch does not match the current mirror")
        if new_coordinator.trust_epoch != approval.new_trust_epoch:
            raise TrustRecoveryError("new coordinator trust epoch does not match the approval")
        actual_identities = tuple(
            new_coordinator.witness_identity(role).identity_digest for role in _ROLES
        )
        if actual_identities != approval.new_nv_identity_digests:
            raise TrustRecoveryError("new NV identities do not match the approval")

        records = []
        for adoption in approval.adoptions:
            content = adopted_contents.get(adoption.namespace)
            if content is None or _content_digest(content) != adoption.adopted_content_digest:
                raise TrustRecoveryError("adopted content does not match the approval")
            if _blob_id(adoption.namespace, content) != adoption.adopted_blob_id:
                raise TrustRecoveryError("adopted blob id does not match the approval")
            current = new_coordinator.current(adoption.namespace)
            genesis = new_coordinator.record_at(adoption.namespace, 0)
            if current is None:
                if genesis is not None:
                    raise TrustRecoveryError("new witness is inconsistent with its recovery genesis")
                genesis = new_coordinator.genesis(
                    adoption.namespace,
                    initial_state_digest=adoption.adopted_state_digest,
                    initial_content=content,
                )
                current = genesis
            elif genesis is None:
                raise TrustRecoveryError("new witness has no authenticated recovery genesis")
            if existing is None and current.generation != 0:
                raise TrustRecoveryError("new witness already contains an unapproved generation")
            if existing is not None:
                if adoption.namespace == "wrapped_key_state" and current.generation != 0:
                    raise TrustRecoveryError("recovered wrapped-key witness advanced outside the approval")
                if adoption.namespace == "audit_head" and (
                    current.generation not in (0, 1)
                    or (current.generation == 1 and current.state_digest != existing.consumption_digest)
                ):
                    raise TrustRecoveryError("recovered audit witness advanced outside the approval")
            if (
                genesis.generation != 0
                or genesis.state_digest != adoption.adopted_state_digest
                or genesis.immutable_blob_id != adoption.adopted_blob_id
            ):
                raise TrustRecoveryError("new witness does not select the approved adopted state")
            records.append(genesis)

        if existing is not None:
            self._witness_consumption(new_coordinator, existing)
            current_count, current_digest = (
                self._authorizations.current_authorizations_for_trust_recovery(
                    new_trust_epoch=existing.new_trust_epoch
                )
            )
            if (
                current_count != existing.invalidated_authorization_count
                or current_digest != existing.invalidated_authorization_digest
            ):
                raise TrustRecoveryError(
                    "recovery replay does not match current mission authorization state"
                )
            mirror = self._epoch.current()
            if (
                mirror is None
                or mirror.trust_epoch != existing.new_trust_epoch
                or mirror.deployment_epoch != existing.deployment_epoch
                or mirror.nv_identity_digest != actual_identities[2]
                or mirror.provider_identity != provider_identity
            ):
                raise TrustRecoveryError("recovery replay does not match the current deployment mirror")
            return existing

        if new_coordinator.witness_is_written("deployment_epoch"):
            deployment_epoch = new_coordinator.read_deployment_epoch()
        else:
            deployment_epoch = new_coordinator.initialize_deployment_epoch()
        discontinuity = self._ds.compute("security_projection_digest", {
            "approval_digest": approval.approval_digest,
            "old_record_digests": tuple(item.last_verified_record_digest for item in approval.adoptions),
            "new_record_digests": tuple(record.record_digest for record in records),
        })
        mirror_fields = {
            "trust_epoch": approval.new_trust_epoch,
            "deployment_epoch": deployment_epoch,
            "nv_identity_digest": actual_identities[2],
            "provider_identity": provider_identity,
            "established_at_iso": now.isoformat(),
        }
        mirror = DeploymentEpochMirror(
            trust_epoch=approval.new_trust_epoch,
            deployment_epoch=deployment_epoch,
            nv_identity_digest=actual_identities[2],
            provider_identity=provider_identity,
            established_at_iso=now.isoformat(),
            record_digest=self._ds.compute("deployment_epoch_digest", mirror_fields),
        )
        with ApplicationUnitOfWork(
            self._db,
            aggregate_name="TrustRecoveryAggregate",
            operation_id=f"consume-{approval.approval_id}",
            input_digest=compute_input_digest({
                "approval_digest": approval.approval_digest,
                "adopted_content_digests": tuple(
                    _content_digest(adopted_contents[namespace]) for namespace in _NAMESPACES
                ),
                "provider_identity": provider_identity,
            }),
        ) as uow:
            if uow.already_applied:
                raise TrustRecoveryError("recovery operation exists without its consumption record")
            self._leases.invalidate_all_in_txn(released_at=now)
            invalidated_count, invalidated_digest = (
                self._authorizations.invalidate_all_authorizations_for_trust_recovery_in_txn(
                    guard=self._guard, new_trust_epoch=approval.new_trust_epoch
                )
            )
            consumption_fields = {
                "consumption_id": f"consume-{approval.approval_id}",
                "approval_id": approval.approval_id,
                "approval_digest": approval.approval_digest,
                "new_trust_epoch": approval.new_trust_epoch,
                "new_witness_digests": tuple(record.witness_digest for record in records),
                "deployment_epoch": deployment_epoch,
                "worker_stop_evidence_digest": stopped,
                "invalidated_authorization_count": invalidated_count,
                "invalidated_authorization_digest": invalidated_digest,
                "audit_discontinuity_digest": discontinuity,
                "consumed_at": now,
            }
            consumption = TrustRecoveryConsumption(
                **consumption_fields,  # type: ignore[arg-type]
                consumption_digest=self._ds.compute("trust_recovery_consumption_digest", consumption_fields),
            )
            self._epoch.replace_in_txn(guard=self._guard, mirror=mirror)
            self._db.occ_insert(
                _CONSUMPTION_NS,
                approval.approval_id,
                1,
                json.dumps(consumption.model_dump(mode="json"), sort_keys=True),
            )
            uow.record_result(consumption.consumption_digest)
        self._fault.check("after_recovery_consumption_commit")
        self._witness_consumption(new_coordinator, consumption)
        return consumption

    def _witness_consumption(
        self,
        coordinator: AuthenticatedGenerationCoordinator,
        consumption: TrustRecoveryConsumption,
    ) -> None:
        current = coordinator.current("audit_head")
        if current is None:
            raise TrustRecoveryError("recovery audit genesis is missing")
        try:
            adopted_state = json.loads(coordinator.record_content(current))
        except (TypeError, ValueError) as exc:
            raise TrustRecoveryError("approved recovery audit content is invalid") from exc
        if not isinstance(adopted_state, dict):
            raise TrustRecoveryError("approved recovery audit content must be an object")
        adopted_state["trust_recovery_consumption"] = consumption.model_dump(mode="json")
        adopted_state["audit_discontinuity_digest"] = consumption.audit_discontinuity_digest
        content = canonical_dumps(adopted_state).decode("utf-8")
        record = coordinator.commit(
            "audit_head",
            new_state_digest=consumption.consumption_digest,
            new_content=content,
            operation_id=f"trust-recovery-consumption-witness-{consumption.approval_id}",
        )
        current = coordinator.current("audit_head")
        if (
            current is None
            or current.witness_digest != record.witness_digest
            or record.state_digest != consumption.consumption_digest
        ):
            raise TrustRecoveryError("recovery approval consumption witness read-back failed")
