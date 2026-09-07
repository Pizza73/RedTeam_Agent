"""Deterministic verified finding projection from trusted execution results."""

from __future__ import annotations

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import KnowledgeStateIntegrityError
from redteam_agent.knowledge.models import VerifiedFinding
from redteam_agent.knowledge.service import KnowledgeService
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.execution_repositories import (
    ExecutionRecordRepository,
    ExecutionResultRepository,
)


class VerifiedFindingProjector:
    def __init__(
        self, *, knowledge_service: KnowledgeService,
        execution_repository: ExecutionRecordRepository,
        result_repository: ExecutionResultRepository,
        digest_service: DigestService, clock: Clock,
    ) -> None:
        self._knowledge = knowledge_service
        self._executions, self._results = execution_repository, result_repository
        self._ds, self._clock = digest_service, clock

    def project_success(self, execution_id: str) -> VerifiedFinding:
        execution = self._executions.get(execution_id)
        result = self._results.get(execution_id)
        if (
            execution is None or result is None or result.status != "SUCCEEDED"
            or execution.result_ingestion_state != "SUCCEEDED"
        ):
            raise KnowledgeStateIntegrityError(
                "verified finding requires a current successful ingested execution"
            )
        source_digest = self._ds.compute(
            "execution_outcome_source_digest", result.model_dump(mode="python")
        )
        fields = {
            "finding_id": f"finding-execution-{execution_id}",
            "mission_id": execution.mission_id, "finding_type": "execution_outcome",
            "subject_ref": execution_id, "predicate": "execution_succeeded",
            "value": "SUCCEEDED", "source_execution_id": execution_id,
            "source_record_digest": source_digest, "verification_state": "confirmed",
            "finding_version": 1, "recorded_at": self._clock.now(),
        }
        finding = VerifiedFinding.model_validate({
            **fields,
            "finding_digest": self._ds.compute("verified_finding_digest", fields),
        })
        return self._knowledge.record_verified_finding(finding)
