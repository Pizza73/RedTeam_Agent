"""Knowledge owner with an explicit TPM-witnessed empty/current head."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import KnowledgeStateIntegrityError
from redteam_agent.knowledge.models import KnowledgeObservation, KnowledgeSecurityHead, VerifiedFinding
from redteam_agent.storage.database import CriticalMutation, Database, UnitOfWork

_HEAD_NS = "knowledge_security_head"
_OBSERVATION_NS = "knowledge_observation"
_FINDING_NS = "verified_finding"


class KnowledgeService:
    def __init__(
        self, *, database: Database, digest_service: DigestService,
        evidence_rule_catalog_digest: str,
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._rule_catalog_digest = evidence_rule_catalog_digest

    def initialize_mission(
        self, *, mission_id: str, mission_revision: int, recorded_at: datetime,
    ) -> KnowledgeSecurityHead:
        existing = self.current_head(mission_id)
        if existing is not None:
            if existing.mission_revision != mission_revision:
                raise KnowledgeStateIntegrityError("knowledge head belongs to another mission revision")
            return existing
        empty = self._ds.compute("security_projection_digest", {"records": ()})
        recorded = recorded_at.astimezone(UTC)
        fields = {
            "head_id": f"knowledge-head-{mission_id}", "mission_id": mission_id,
            "mission_revision": mission_revision, "security_version": 1,
            "previous_head_digest": None, "fact_state_root_digest": empty,
            "entity_state_root_digest": empty, "source_state_root_digest": empty,
            "evidence_rule_catalog_digest": self._rule_catalog_digest, "recorded_at": recorded,
        }
        head = KnowledgeSecurityHead(
            head_id=f"knowledge-head-{mission_id}", mission_id=mission_id,
            mission_revision=mission_revision, security_version=1, previous_head_digest=None,
            fact_state_root_digest=empty, entity_state_root_digest=empty,
            source_state_root_digest=empty, evidence_rule_catalog_digest=self._rule_catalog_digest,
            recorded_at=recorded,
            head_digest=self._ds.compute("knowledge_security_head_digest", fields),
        )
        with UnitOfWork(self._db):
            self._db.occ_insert(_HEAD_NS, mission_id, 1, _dump(head))
            self._db.record_critical_mutation(CriticalMutation(
                mission_id=mission_id, event_type="KNOWLEDGE_EVIDENCE_CHANGED",
                actor_id="knowledge-service", occurred_at_iso=head.recorded_at.isoformat(),
                record_type="knowledge_evidence_head", record_id=mission_id,
                state_version=head.security_version,
                security_projection_digest=head.head_digest,
            ))
        self.verify_current_head(mission_id)
        return head

    def current_head(self, mission_id: str) -> KnowledgeSecurityHead | None:
        row = self._db.occ_get(_HEAD_NS, mission_id)
        if row is None:
            return None
        head = KnowledgeSecurityHead.model_validate_json(row[1])
        if head.mission_id != mission_id or row[0] != head.security_version:
            raise KnowledgeStateIntegrityError("knowledge head identity/version mismatch")
        payload = head.model_dump(mode="python")
        expected = payload.pop("head_digest")
        self._ds.verify("knowledge_security_head_digest", payload, expected)
        return head

    def verify_current_head(self, mission_id: str) -> KnowledgeSecurityHead:
        head = self.current_head(mission_id)
        if head is None:
            raise KnowledgeStateIntegrityError("explicit Knowledge head is missing")
        if head.evidence_rule_catalog_digest != self._rule_catalog_digest:
            raise KnowledgeStateIntegrityError("Knowledge evidence rule catalog changed")
        return head

    def record_observation(self, observation: KnowledgeObservation) -> KnowledgeObservation:
        """Persist unconfirmed data without changing the witnessed fact head."""
        payload = observation.model_dump(mode="python")
        expected = payload.pop("observation_digest")
        self._ds.verify("knowledge_observation_digest", payload, expected)
        self.verify_current_head(observation.mission_id)
        with UnitOfWork(self._db):
            self._db.occ_insert_idempotent(
                _OBSERVATION_NS, observation.observation_id, 1, _dump(observation)
            )
        return observation

    def observations(self, mission_id: str) -> tuple[KnowledgeObservation, ...]:
        result = []
        for key, _version, text in self._db.occ_get_all(_OBSERVATION_NS):
            observation = KnowledgeObservation.model_validate_json(text)
            if observation.observation_id != key:
                raise KnowledgeStateIntegrityError("observation row identity mismatch")
            payload = observation.model_dump(mode="python")
            expected = payload.pop("observation_digest")
            self._ds.verify("knowledge_observation_digest", payload, expected)
            if observation.mission_id == mission_id:
                result.append(observation)
        return tuple(sorted(result, key=lambda item: item.observation_id))

    def record_verified_finding(self, finding: VerifiedFinding) -> VerifiedFinding:
        payload = finding.model_dump(mode="python")
        expected = payload.pop("finding_digest")
        self._ds.verify("verified_finding_digest", payload, expected)
        existing = self._db.occ_get(_FINDING_NS, finding.finding_id)
        if existing is not None:
            stored = VerifiedFinding.model_validate_json(existing[1])
            if stored != finding or existing[0] != finding.finding_version:
                raise KnowledgeStateIntegrityError("verified finding identity conflict")
            return stored
        head = self.verify_current_head(finding.mission_id)
        next_version = head.security_version + 1
        fact_root = self._ds.compute("security_projection_digest", {
            "previous_root": head.fact_state_root_digest,
            "finding_id": finding.finding_id,
            "finding_digest": finding.finding_digest,
        })
        fields = {
            "head_id": head.head_id, "mission_id": head.mission_id,
            "mission_revision": head.mission_revision, "security_version": next_version,
            "previous_head_digest": head.head_digest, "fact_state_root_digest": fact_root,
            "entity_state_root_digest": head.entity_state_root_digest,
            "source_state_root_digest": head.source_state_root_digest,
            "evidence_rule_catalog_digest": head.evidence_rule_catalog_digest,
            "recorded_at": finding.recorded_at,
        }
        next_head = KnowledgeSecurityHead.model_validate({
            **fields,
            "head_digest": self._ds.compute("knowledge_security_head_digest", fields),
        })
        with UnitOfWork(self._db):
            self._db.occ_insert_idempotent(
                _FINDING_NS, finding.finding_id, finding.finding_version, _dump(finding)
            )
            self._db.occ_update(
                _HEAD_NS, finding.mission_id, expected_version=head.security_version,
                new_version=next_version, json_text=_dump(next_head),
            )
            self._db.record_critical_mutation(CriticalMutation(
                mission_id=finding.mission_id, event_type="KNOWLEDGE_EVIDENCE_CHANGED",
                actor_id="verified-finding-projector", occurred_at_iso=finding.recorded_at.isoformat(),
                record_type="knowledge_evidence_head", record_id=finding.mission_id,
                state_version=next_version, security_projection_digest=next_head.head_digest,
            ))
        return finding


def _dump(value: KnowledgeSecurityHead | KnowledgeObservation | VerifiedFinding) -> str:
    return json.dumps(value.model_dump(mode="json"), sort_keys=True)
