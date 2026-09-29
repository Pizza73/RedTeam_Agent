"""Strong-key-only canonical entity resolution."""

from __future__ import annotations

import json
from typing import Literal

from pydantic import Field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import KnowledgeStateIntegrityError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.storage.database import Database, UnitOfWork

EntityType = Literal[
    "host", "ad_principal", "windows_local_principal", "linux_principal",
    "domain", "session", "network_asset",
]
_STRONG_KEYS: dict[EntityType, frozenset[str]] = {
    "host": frozenset({"provider_stable_host_id", "machine_sid"}),
    "ad_principal": frozenset({"domain_sid+principal_sid"}),
    "windows_local_principal": frozenset({"host_strong_key+principal_sid"}),
    "linux_principal": frozenset({"verified_host_id+uid"}),
    "domain": frozenset({"domain_sid", "registered_domain_id"}),
    "session": frozenset({"provider_identity+stable_session_id"}),
    "network_asset": frozenset({"mission_asset_id+address"}),
}


class CanonicalEntityRecord(StrictImmutableBoundaryModel):
    entity_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    entity_type: EntityType
    strong_key_type: str = Field(min_length=1)
    strong_key_value: str = Field(min_length=1)
    source_reference_ids: tuple[str, ...]
    entity_version: int = Field(ge=1)
    record_digest: str = Field(min_length=1)


class EntityResolutionCandidate(StrictImmutableBoundaryModel):
    candidate_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    left_entity_or_alias_ref: str = Field(min_length=1)
    right_entity_or_alias_ref: str = Field(min_length=1)
    status: Literal["candidate_match", "conflict"]
    reason_code: Literal["ALIAS_ONLY", "STRONG_KEY_CONFLICT"]
    evidence_reference_ids: tuple[str, ...]
    candidate_digest: str = Field(min_length=1)


class EntityResolver:
    def __init__(self, *, database: Database, digest_service: DigestService) -> None:
        self._db, self._ds = database, digest_service

    def resolve_strong(
        self, *, mission_id: str, entity_type: EntityType, strong_key_type: str,
        strong_key_value: str, source_reference_ids: tuple[str, ...],
    ) -> CanonicalEntityRecord:
        if strong_key_type not in _STRONG_KEYS[entity_type]:
            raise KnowledgeStateIntegrityError("entity cannot auto-merge without a registered strong key")
        identity = self._ds.compute("security_projection_digest", {
            "mission_id": mission_id, "entity_type": entity_type,
            "strong_key_type": strong_key_type, "strong_key_value": strong_key_value,
        })
        entity_id = f"entity-{identity[:24]}"
        current = self.get(entity_id)
        if current is not None and (
            current.mission_id != mission_id
            or current.entity_type != entity_type
            or current.strong_key_type != strong_key_type
            or current.strong_key_value != strong_key_value
        ):
            raise KnowledgeStateIntegrityError("canonical entity strong-key collision")
        combined_sources = tuple(sorted(set(
            source_reference_ids if current is None
            else (*current.source_reference_ids, *source_reference_ids)
        )))
        version = 1 if current is None else current.entity_version + 1
        if current is not None and combined_sources == current.source_reference_ids:
            return current
        fields = {
            "entity_id": entity_id, "mission_id": mission_id, "entity_type": entity_type,
            "strong_key_type": strong_key_type, "strong_key_value": strong_key_value,
            "source_reference_ids": combined_sources, "entity_version": version,
        }
        record = CanonicalEntityRecord.model_validate({
            **fields, "record_digest": self._ds.compute("canonical_entity_digest", fields)
        })
        with UnitOfWork(self._db):
            text = json.dumps(record.model_dump(mode="json"), sort_keys=True)
            if current is None:
                self._db.occ_insert("canonical_entity", entity_id, 1, text)
            else:
                self._db.occ_update(
                    "canonical_entity", entity_id,
                    expected_version=current.entity_version,
                    new_version=record.entity_version,
                    json_text=text,
                )
        return record

    def get(self, entity_id: str) -> CanonicalEntityRecord | None:
        row = self._db.occ_get("canonical_entity", entity_id)
        if row is None:
            return None
        record = CanonicalEntityRecord.model_validate_json(row[1])
        if record.entity_id != entity_id or record.entity_version != row[0]:
            raise KnowledgeStateIntegrityError("canonical entity identity or version mismatch")
        payload = record.model_dump(mode="python")
        expected = payload.pop("record_digest")
        self._ds.verify("canonical_entity_digest", payload, expected)
        return record

    def record_alias_candidate(
        self, *, mission_id: str, left_ref: str, right_ref: str,
        evidence_reference_ids: tuple[str, ...], conflict: bool = False,
    ) -> EntityResolutionCandidate:
        fields = {
            "mission_id": mission_id, "left_entity_or_alias_ref": left_ref,
            "right_entity_or_alias_ref": right_ref,
            "status": "conflict" if conflict else "candidate_match",
            "reason_code": "STRONG_KEY_CONFLICT" if conflict else "ALIAS_ONLY",
            "evidence_reference_ids": tuple(sorted(set(evidence_reference_ids))),
        }
        digest = self._ds.compute("entity_resolution_candidate_digest", {
            "candidate_id": "pending", **fields
        })
        candidate_id = f"entity-candidate-{digest[:24]}"
        payload = {"candidate_id": candidate_id, **fields}
        candidate = EntityResolutionCandidate.model_validate({
            **payload,
            "candidate_digest": self._ds.compute("entity_resolution_candidate_digest", payload),
        })
        with UnitOfWork(self._db):
            self._db.occ_insert_idempotent(
                "entity_resolution_candidate", candidate_id, 1,
                json.dumps(candidate.model_dump(mode="json"), sort_keys=True),
            )
        return candidate
