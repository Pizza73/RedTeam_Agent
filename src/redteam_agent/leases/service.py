"""Deployment-epoch mirror service + typed collection/ingestion lease service (SystemDesign §10.3).

Every normal worker durable mutation validates the *current* stored lease under one
transaction: lease id, owner, trust/deployment epoch (against the mirror), fencing
token, not released, an unexpired host-shared monotonic deadline, the immutable
authority/resource digest and the expected state version. UTC rollback / divergence is
surfaced by the :class:`ClockIntegrityGuard` read inside the predicate. A takeover of an
expired lease always assigns a strictly larger fence, so a stale (non-cooperative)
writer's mutation fails the predicate.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from redteam_agent.audit.generation import AuthenticatedGenerationCoordinator
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import DeploymentEpochError, LeaseError
from redteam_agent.execution.models import (
    LeaseFence,
    ResultCollectionLease,
    ResultTaskBinding,
    SecureIngestionLease,
)
from redteam_agent.execution.records import finalize_object_digest
from redteam_agent.leases.models import DeploymentEpochMirror, LeasePolicy
from redteam_agent.runtime.clock import ClockIntegrityGuard
from redteam_agent.storage.database import Database
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.unit_of_work import ApplicationUnitOfWork, compute_input_digest

_EPOCH_NS = "deployment_epoch_mirror"
_EPOCH_KEY = "current"
_COLLECTION_NS = "collection_lease"
_INGESTION_NS = "ingestion_lease"


class DeploymentEpochService:
    """Establishes and reads the single deployment-epoch mirror (composition-owned)."""

    def __init__(self, database: Database, digest_service: DigestService, write_guard: WriteGuard) -> None:
        self._db = database
        self._ds = digest_service
        self._guard = write_guard

    def establish(
        self, *, guard: WriteGuard, trust_epoch: int, deployment_epoch: int,
        nv_identity_digest: str, provider_identity: str, established_at_iso: str,
    ) -> DeploymentEpochMirror:
        if guard is not self._guard:
            raise DeploymentEpochError("deployment epoch mirror is composition-owned")
        payload = {
            "trust_epoch": trust_epoch, "deployment_epoch": deployment_epoch,
            "nv_identity_digest": nv_identity_digest, "provider_identity": provider_identity,
            "established_at_iso": established_at_iso,
        }
        mirror = DeploymentEpochMirror(
            **payload,  # type: ignore[arg-type]
            record_digest=self._ds.compute("deployment_epoch_digest", payload),
        )
        op = compute_input_digest(payload)
        with ApplicationUnitOfWork(
            self._db, aggregate_name="DeploymentEpochAggregate", operation_id=f"epoch-{deployment_epoch}",
            input_digest=op,
        ) as uow:
            if not uow.already_applied:
                self.replace_in_txn(guard=guard, mirror=mirror)
                uow.record_result(mirror.record_digest)
        return mirror

    def replace_in_txn(self, *, guard: WriteGuard, mirror: DeploymentEpochMirror) -> None:
        """Composition/recovery-only mirror replacement inside an existing UoW."""
        if guard is not self._guard or not self._db.in_transaction:
            raise DeploymentEpochError("deployment epoch replacement requires the composition transaction")
        payload = {k: v for k, v in mirror.model_dump(mode="python").items() if k != "record_digest"}
        self._ds.verify("deployment_epoch_digest", payload, mirror.record_digest)
        existing = self._db.occ_get(_EPOCH_NS, _EPOCH_KEY)
        text = json.dumps(mirror.model_dump(mode="json"), sort_keys=True)
        if existing is None:
            self._db.occ_insert(_EPOCH_NS, _EPOCH_KEY, 1, text)
        else:
            self._db.occ_update(
                _EPOCH_NS, _EPOCH_KEY, expected_version=existing[0],
                new_version=existing[0] + 1, json_text=text,
            )

    def current(self) -> DeploymentEpochMirror | None:
        row = self._db.occ_get(_EPOCH_NS, _EPOCH_KEY)
        if row is None:
            return None
        mirror = DeploymentEpochMirror.model_validate_json(row[1])
        payload = {k: v for k, v in mirror.model_dump(mode="python").items() if k != "record_digest"}
        self._ds.verify("deployment_epoch_digest", payload, mirror.record_digest)
        return mirror

    def verify_against_tpm(self, coordinator: AuthenticatedGenerationCoordinator) -> DeploymentEpochMirror:
        mirror = self.current()
        if mirror is None:
            raise DeploymentEpochError("deployment epoch mirror is not established")
        measured = coordinator.read_deployment_epoch()
        if measured != mirror.deployment_epoch:
            raise DeploymentEpochError("deployment epoch mirror disagrees with the TPM counter")
        if mirror.trust_epoch != coordinator.trust_epoch:
            raise DeploymentEpochError("deployment epoch mirror trust epoch disagrees with the anchor")
        return mirror


class LeaseService:
    def __init__(
        self,
        *,
        database: Database,
        digest_service: DigestService,
        clock_guard: ClockIntegrityGuard,
        epoch_service: DeploymentEpochService,
        write_guard: WriteGuard,
        policy: LeasePolicy | None = None,
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._guard_clock = clock_guard
        self._epoch = epoch_service
        self._guard = write_guard
        self._policy = policy if policy is not None else LeasePolicy()

    @property
    def policy(self) -> LeasePolicy:
        return self._policy

    # --- fence / deadline helpers ----------------------------------------

    def _mirror(self) -> DeploymentEpochMirror:
        mirror = self._epoch.current()
        if mirror is None:
            raise LeaseError("no deployment epoch mirror; cannot issue leases")
        return mirror

    def _next_fence(self, previous: LeaseFence | None) -> LeaseFence:
        mirror = self._mirror()
        if previous is not None and previous.deployment_epoch == mirror.deployment_epoch \
                and previous.trust_epoch == mirror.trust_epoch:
            token = previous.fencing_token + 1
        else:
            token = 1
        return LeaseFence(trust_epoch=mirror.trust_epoch, deployment_epoch=mirror.deployment_epoch,
                          fencing_token=token)

    def _deadline(self, *, caps: tuple[datetime, ...]) -> tuple[datetime, int]:
        reading = self._guard_clock.read()  # raises ClockIntegrityError on rollback/divergence
        expires = reading.utc + timedelta(seconds=self._policy.lease_duration_seconds)
        for cap in caps:
            expires = min(expires, cap)
        deadline_ns = reading.monotonic_ns + int((expires - reading.utc).total_seconds() * 1_000_000_000)
        return expires, deadline_ns

    # --- collection leases ------------------------------------------------

    def get_collection_lease(self, collection_id: str) -> ResultCollectionLease | None:
        row = self._db.occ_get(_COLLECTION_NS, collection_id)
        if row is None:
            return None
        lease = ResultCollectionLease.model_validate_json(row[1])
        self._verify_digest(lease.model_dump(mode="python"), "collection_lease_digest", lease.record_digest)
        return lease

    def acquire_collection_lease(
        self, *, collection_id: str, execution_id: str, authority_digest: str,
        task_binding: ResultTaskBinding, sink_id: str, owner_id: str,
        expected_execution_state_version: int, caps: tuple[datetime, ...],
    ) -> ResultCollectionLease:
        previous = self.get_collection_lease(collection_id)
        if previous is not None and previous.released_at is None and not self._is_expired(previous):
            raise LeaseError("collection lease is held by a live owner; cannot acquire")
        fence = self._next_fence(previous.fence if previous is not None else None)
        expires, deadline_ns = self._deadline(caps=caps)
        reading_utc = self._guard_clock.read().utc
        lease = self._finalize_collection(ResultCollectionLease(
            collection_id=collection_id, execution_id=execution_id, authority_digest=authority_digest,
            task_binding=task_binding, sink_id=sink_id, owner_id=owner_id,
            lease_id=f"lease-{collection_id}-{fence.deployment_epoch}-{fence.fencing_token}", fence=fence,
            expected_execution_state_version=expected_execution_state_version, acquired_at=reading_utc,
            lease_expires_at=expires, lease_deadline_monotonic_ns=deadline_ns, released_at=None,
            updated_at=reading_utc, record_digest="pending",
        ))
        self._store_collection(collection_id, lease)
        return lease

    def renew_collection_lease(
        self, *, collection_id: str, owner_id: str, caps: tuple[datetime, ...]
    ) -> ResultCollectionLease:
        current = self.get_collection_lease(collection_id)
        if current is None or current.released_at is not None or current.owner_id != owner_id:
            raise LeaseError("cannot renew a released/foreign/absent collection lease")
        if self._is_expired(current):
            raise LeaseError("cannot renew an expired collection lease")
        expires, deadline_ns = self._deadline(caps=caps)
        # Renewal advances only the deadline and audit fields, never authority/state/fence.
        renewed = self._finalize_collection(current.model_copy(update={
            "lease_expires_at": expires, "lease_deadline_monotonic_ns": deadline_ns,
            "updated_at": self._guard_clock.read().utc, "record_digest": "pending",
        }))
        self._store_collection(collection_id, renewed)
        return renewed

    def takeover_collection_lease(
        self, *, collection_id: str, execution_id: str, authority_digest: str,
        task_binding: ResultTaskBinding, sink_id: str, new_owner_id: str,
        expected_execution_state_version: int, caps: tuple[datetime, ...],
    ) -> ResultCollectionLease:
        previous = self.get_collection_lease(collection_id)
        if previous is not None and previous.released_at is None and not self._is_expired(previous):
            raise LeaseError("cannot take over a live collection lease")
        return self.acquire_collection_lease(
            collection_id=collection_id, execution_id=execution_id, authority_digest=authority_digest,
            task_binding=task_binding, sink_id=sink_id, owner_id=new_owner_id,
            expected_execution_state_version=expected_execution_state_version, caps=caps,
        )

    def release_collection_lease(self, *, collection_id: str, owner_id: str) -> None:
        current = self.get_collection_lease(collection_id)
        if current is None or current.owner_id != owner_id:
            raise LeaseError("cannot release a foreign/absent collection lease")
        released = self._finalize_collection(current.model_copy(update={
            "released_at": self._guard_clock.read().utc, "updated_at": self._guard_clock.read().utc,
            "record_digest": "pending",
        }))
        self._store_collection(collection_id, released)

    def validate_collection_lease(
        self, *, collection_id: str, owner_id: str, lease_id: str, fence: LeaseFence,
        authority_digest: str, expected_execution_state_version: int,
    ) -> ResultCollectionLease:
        """Full predicate (reloads the current lease); raises :class:`LeaseError`/`ClockIntegrityError`."""
        current = self.get_collection_lease(collection_id)
        self._validate_common(
            current=current, owner_id=owner_id, lease_id=lease_id, fence=fence,
            authority_digest=None if current is None else current.authority_digest,
            expected_authority_digest=authority_digest,
            expected_state_version=expected_execution_state_version,
            current_state_version=None if current is None else current.expected_execution_state_version,
        )
        assert current is not None
        return current

    # --- ingestion leases -------------------------------------------------

    def get_ingestion_lease(self, ingestion_id: str) -> SecureIngestionLease | None:
        row = self._db.occ_get(_INGESTION_NS, ingestion_id)
        if row is None:
            return None
        lease = SecureIngestionLease.model_validate_json(row[1])
        self._verify_digest(lease.model_dump(mode="python"), "ingestion_lease_digest", lease.record_digest)
        return lease

    def acquire_ingestion_lease(
        self, *, ingestion_id: str, execution_id: str, receipt_digest: str, quarantine_digest: str,
        evidence_retention_until: datetime, owner_id: str, expected_ingestion_state_version: int,
        caps: tuple[datetime, ...],
    ) -> SecureIngestionLease:
        previous = self.get_ingestion_lease(ingestion_id)
        if previous is not None and previous.released_at is None and not self._is_expired(previous):
            raise LeaseError("ingestion lease is held by a live owner; cannot acquire")
        fence = self._next_fence(previous.fence if previous is not None else None)
        expires, deadline_ns = self._deadline(caps=(*caps, evidence_retention_until))
        reading_utc = self._guard_clock.read().utc
        lease = self._finalize_ingestion(SecureIngestionLease(
            ingestion_id=ingestion_id, execution_id=execution_id, receipt_digest=receipt_digest,
            quarantine_digest=quarantine_digest, evidence_retention_until=evidence_retention_until,
            owner_id=owner_id, lease_id=f"ilease-{ingestion_id}-{fence.deployment_epoch}-{fence.fencing_token}",
            fence=fence, expected_ingestion_state_version=expected_ingestion_state_version,
            acquired_at=reading_utc, lease_expires_at=expires, lease_deadline_monotonic_ns=deadline_ns,
            released_at=None, updated_at=reading_utc, record_digest="pending",
        ))
        self._store_ingestion(ingestion_id, lease)
        return lease

    def release_ingestion_lease(self, *, ingestion_id: str, owner_id: str) -> None:
        current = self.get_ingestion_lease(ingestion_id)
        if current is None or current.owner_id != owner_id:
            raise LeaseError("cannot release a foreign/absent ingestion lease")
        released = self._finalize_ingestion(current.model_copy(update={
            "released_at": self._guard_clock.read().utc, "updated_at": self._guard_clock.read().utc,
            "record_digest": "pending",
        }))
        self._store_ingestion(ingestion_id, released)

    def invalidate_ingestion_lease(self, *, ingestion_id: str) -> None:
        """Retention-scheduler authority: mark the current ingestion lease released.

        Unlike a worker release, this does not require the caller to be the owner; the
        fence is preserved (never deleted/reused) so a stale worker still fails validate.
        """
        current = self.get_ingestion_lease(ingestion_id)
        if current is None or current.released_at is not None:
            return
        released = self._finalize_ingestion(current.model_copy(update={
            "released_at": self._guard_clock.read().utc, "updated_at": self._guard_clock.read().utc,
            "record_digest": "pending",
        }))
        self._store_ingestion(ingestion_id, released)

    def invalidate_collection_lease(self, *, collection_id: str) -> None:
        current = self.get_collection_lease(collection_id)
        if current is None or current.released_at is not None:
            return
        released = self._finalize_collection(current.model_copy(update={
            "released_at": self._guard_clock.read().utc, "updated_at": self._guard_clock.read().utc,
            "record_digest": "pending",
        }))
        self._store_collection(collection_id, released)

    def invalidate_all_in_txn(self, *, released_at: datetime) -> tuple[int, int]:
        """Invalidate every old-epoch lease during stopped-worker trust recovery."""
        if not self._db.in_transaction:
            raise LeaseError("global lease invalidation requires the recovery transaction")
        collection_count = 0
        ingestion_count = 0
        for key, version, text in self._db.occ_get_all(_COLLECTION_NS):
            collection_lease = ResultCollectionLease.model_validate_json(text)
            if collection_lease.released_at is None:
                released = self._finalize_collection(collection_lease.model_copy(update={
                    "released_at": released_at, "updated_at": released_at, "record_digest": "pending",
                }))
                self._db.occ_update(
                    _COLLECTION_NS, key, expected_version=version, new_version=version + 1,
                    json_text=json.dumps(released.model_dump(mode="json"), sort_keys=True),
                )
                collection_count += 1
        for key, version, text in self._db.occ_get_all(_INGESTION_NS):
            ingestion_lease = SecureIngestionLease.model_validate_json(text)
            if ingestion_lease.released_at is None:
                released_ingestion = self._finalize_ingestion(ingestion_lease.model_copy(update={
                    "released_at": released_at, "updated_at": released_at, "record_digest": "pending",
                }))
                self._db.occ_update(
                    _INGESTION_NS, key, expected_version=version, new_version=version + 1,
                    json_text=json.dumps(released_ingestion.model_dump(mode="json"), sort_keys=True),
                )
                ingestion_count += 1
        return collection_count, ingestion_count

    def validate_ingestion_lease(
        self, *, ingestion_id: str, owner_id: str, lease_id: str, fence: LeaseFence,
        quarantine_digest: str, expected_ingestion_state_version: int,
    ) -> SecureIngestionLease:
        current = self.get_ingestion_lease(ingestion_id)
        self._validate_common(
            current=current, owner_id=owner_id, lease_id=lease_id, fence=fence,
            authority_digest=None if current is None else current.quarantine_digest,
            expected_authority_digest=quarantine_digest,
            expected_state_version=expected_ingestion_state_version,
            current_state_version=None if current is None else current.expected_ingestion_state_version,
        )
        assert current is not None
        return current

    # --- shared internals -------------------------------------------------

    def _validate_common(
        self, *, current: ResultCollectionLease | SecureIngestionLease | None, owner_id: str, lease_id: str,
        fence: LeaseFence, authority_digest: str | None, expected_authority_digest: str,
        expected_state_version: int, current_state_version: int | None,
    ) -> None:
        if current is None or current.released_at is not None:
            raise LeaseError("lease is absent or released")
        if current.lease_id != lease_id or current.owner_id != owner_id:
            raise LeaseError("lease id / owner mismatch (stale worker)")
        if current.fence != fence:
            raise LeaseError("lease fence mismatch (stale fence)")
        mirror = self._mirror()
        if fence.deployment_epoch != mirror.deployment_epoch or fence.trust_epoch != mirror.trust_epoch:
            raise LeaseError("lease epoch mismatch against the deployment mirror")
        reading = self._guard_clock.read()  # ClockIntegrityError on rollback / divergence
        if reading.monotonic_ns >= current.lease_deadline_monotonic_ns:
            raise LeaseError("lease has expired on the monotonic deadline")
        if authority_digest != expected_authority_digest:
            raise LeaseError("lease authority/resource binding mismatch")
        if current_state_version != expected_state_version:
            raise LeaseError("lease expected state version mismatch")

    def _is_expired(self, lease: ResultCollectionLease | SecureIngestionLease) -> bool:
        return self._guard_clock.read().monotonic_ns >= lease.lease_deadline_monotonic_ns

    def _finalize_collection(self, lease: ResultCollectionLease) -> ResultCollectionLease:
        return finalize_object_digest(
            lease, digest_field="record_digest", digest_name="collection_lease_digest", digest_service=self._ds
        )

    def _finalize_ingestion(self, lease: SecureIngestionLease) -> SecureIngestionLease:
        return finalize_object_digest(
            lease, digest_field="record_digest", digest_name="ingestion_lease_digest", digest_service=self._ds
        )

    def _store_collection(self, collection_id: str, lease: ResultCollectionLease) -> None:
        self._upsert(_COLLECTION_NS, collection_id, json.dumps(lease.model_dump(mode="json"), sort_keys=True))

    def _store_ingestion(self, ingestion_id: str, lease: SecureIngestionLease) -> None:
        self._upsert(_INGESTION_NS, ingestion_id, json.dumps(lease.model_dump(mode="json"), sort_keys=True))

    def _upsert(self, namespace: str, key: str, text: str) -> None:
        own_txn = not self._db.in_transaction
        if own_txn:
            self._db.connection.execute("BEGIN")
        try:
            existing = self._db.occ_get(namespace, key)
            if existing is None:
                self._db.occ_insert(namespace, key, 1, text)
            else:
                self._db.occ_update(namespace, key, expected_version=existing[0],
                                    new_version=existing[0] + 1, json_text=text)
        except BaseException:
            if own_txn:
                self._db.connection.rollback()
            raise
        if own_txn:
            self._db.connection.commit()

    def _verify_digest(self, model_payload: dict[str, object], digest_name: str, expected: str) -> None:
        payload = {k: v for k, v in model_payload.items() if k != "record_digest"}
        self._ds.verify(digest_name, payload, expected)
