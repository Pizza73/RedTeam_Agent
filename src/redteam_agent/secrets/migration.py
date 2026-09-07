"""Deterministic read-only legacy secret migration (SystemDesign §34 / §38).

Each legacy ``secret_reference_id`` migrates one-to-one to an archive metadata record
whose logical id is derived deterministically from ``mission_id`` + legacy id. Different
credentials are never aggregated, an old ``confirmed`` is never treated as a current
operator confirmation, and there is no plaintext re-import or compatibility loader. An
ambiguous, missing or digest-mismatched history stops with
:class:`SecretMigrationRequiredError`. Archived records are read-only: they are not
usable for new dispatch, which requires an explicit new registration/confirmation.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import Field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import SecretMigrationRequiredError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.storage.database import Database
from redteam_agent.storage.unit_of_work import ApplicationUnitOfWork, compute_input_digest

_ARCHIVE_NS = "secret_legacy_archive"


class LegacySecretReference(StrictImmutableBoundaryModel):
    legacy_reference_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    legacy_state: Literal["detected", "confirmed", "revoked"]
    legacy_state_digest: str = Field(min_length=1)
    legacy_ciphertext_digest: str = Field(min_length=1)
    legacy_key_metadata_digest: str = Field(min_length=1)
    audit_provenance_digest: str = Field(min_length=1)


class LegacySecretArchiveRecord(StrictImmutableBoundaryModel):
    archive_id: str = Field(min_length=1)
    logical_secret_id: str = Field(min_length=1)
    legacy_reference_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    # An old "confirmed" is archived as an unusable historical state, never as a current
    # operator_review confirmation; an old "revoked" is a tombstone.
    archived_state: Literal["ARCHIVED_DETECTED", "ARCHIVED_CONFIRMED", "REVOKED_TOMBSTONE"]
    legacy_state_digest: str = Field(min_length=1)
    legacy_ciphertext_digest: str = Field(min_length=1)
    legacy_key_metadata_digest: str = Field(min_length=1)
    audit_provenance_digest: str = Field(min_length=1)
    usable_for_dispatch: Literal[False] = False
    archive_digest: str = Field(min_length=1)


_STATE_MAP: dict[str, str] = {
    "detected": "ARCHIVED_DETECTED",
    "confirmed": "ARCHIVED_CONFIRMED",
    "revoked": "REVOKED_TOMBSTONE",
}


class LegacySecretMigrator:
    def __init__(self, database: Database, digest_service: DigestService) -> None:
        self._db = database
        self._ds = digest_service

    def logical_id(self, mission_id: str, legacy_reference_id: str) -> str:
        return f"legacy:{mission_id}:{legacy_reference_id}"

    def get_archive(self, archive_id: str) -> LegacySecretArchiveRecord | None:
        row = self._db.occ_get(_ARCHIVE_NS, archive_id)
        if row is None:
            return None
        record = LegacySecretArchiveRecord.model_validate_json(row[1])
        self._ds.verify("migration_plan_digest",
                        {k: v for k, v in record.model_dump(mode="python").items() if k != "archive_digest"},
                        record.archive_digest)
        return record

    def migrate(self, references: tuple[LegacySecretReference, ...]) -> tuple[LegacySecretArchiveRecord, ...]:
        seen_digest: dict[str, str] = {}
        planned: list[LegacySecretArchiveRecord] = []
        for reference in references:
            logical = self.logical_id(reference.mission_id, reference.legacy_reference_id)
            fields = {
                "archive_id": f"archive:{logical}", "logical_secret_id": logical,
                "legacy_reference_id": reference.legacy_reference_id, "mission_id": reference.mission_id,
                "archived_state": _STATE_MAP[reference.legacy_state],
                "legacy_state_digest": reference.legacy_state_digest,
                "legacy_ciphertext_digest": reference.legacy_ciphertext_digest,
                "legacy_key_metadata_digest": reference.legacy_key_metadata_digest,
                "audit_provenance_digest": reference.audit_provenance_digest, "usable_for_dispatch": False,
            }
            record = LegacySecretArchiveRecord(
                **fields,  # type: ignore[arg-type]
                archive_digest=self._ds.compute("migration_plan_digest", fields),
            )
            # A duplicate/ambiguous legacy history maps to one archive id with conflicting
            # content: stop rather than aggregate.
            if record.archive_id in seen_digest and seen_digest[record.archive_id] != record.archive_digest:
                raise SecretMigrationRequiredError("ambiguous legacy history for one logical id")
            seen_digest[record.archive_id] = record.archive_digest
            existing = self.get_archive(record.archive_id)
            if existing is not None and existing.archive_digest != record.archive_digest:
                raise SecretMigrationRequiredError("legacy archive digest mismatch (non-idempotent migration)")
            planned.append(record)
        op = compute_input_digest([r.archive_id for r in planned])
        with ApplicationUnitOfWork(
            self._db, aggregate_name="SecretLifecycleAggregate", operation_id=f"legacy-migration-{op[:16]}",
            input_digest=op,
        ) as uow:
            if not uow.already_applied:
                for record in planned:
                    self._db.occ_insert_idempotent(
                        _ARCHIVE_NS, record.archive_id, 1,
                        json.dumps(record.model_dump(mode="json"), sort_keys=True),
                    )
                uow.record_result(op)
        return tuple(planned)
