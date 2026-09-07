"""Analyzer proposal reducer with current execution/evidence rebinding."""

from __future__ import annotations

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import KnowledgeStateIntegrityError
from redteam_agent.knowledge.models import AnalyzerCandidateObservation, KnowledgeObservation
from redteam_agent.knowledge.service import KnowledgeService
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.execution_repositories import (
    ExecutionRecordRepository,
    ExecutionResultRepository,
)


class KnowledgeReducer:
    def __init__(
        self, *, knowledge_service: KnowledgeService,
        execution_repository: ExecutionRecordRepository,
        result_repository: ExecutionResultRepository,
        context_resolver: AuthorizationContextResolver,
        digest_service: DigestService, clock: Clock,
    ) -> None:
        self._knowledge = knowledge_service
        self._executions = execution_repository
        self._results = result_repository
        self._resolver = context_resolver
        self._ds = digest_service
        self._clock = clock

    def reduce(self, candidate: AnalyzerCandidateObservation) -> KnowledgeObservation:
        execution = self._executions.get(candidate.source_execution_id)
        result = self._results.get(candidate.source_execution_id)
        if execution is None or result is None or result.status != "SUCCEEDED":
            raise KnowledgeStateIntegrityError("Analyzer source execution result is not current and successful")
        mission = self._resolver.resolve(execution.mission_id, now=self._clock.now()).mission
        condition_ids = {condition.condition_id for condition in mission.success_conditions}
        if candidate.condition_id not in condition_ids:
            raise KnowledgeStateIntegrityError("Analyzer candidate condition does not exist in the mission")
        if not set(candidate.source_artifact_ids) <= set(result.redacted_artifact_ids):
            raise KnowledgeStateIntegrityError("Analyzer candidate references an unrelated artifact")
        fields = {
            "observation_id": candidate.observation_id,
            "mission_id": execution.mission_id,
            "source_execution_id": execution.execution_id,
            "observation_type": candidate.observation_type,
            "subject_ref": candidate.subject_ref,
            "predicate": candidate.predicate,
            "object_ref": candidate.object_ref,
            "attributes": candidate.attributes,
            "source_artifact_ids": candidate.source_artifact_ids,
            "llm_confidence": candidate.llm_confidence,
            "observed_at": self._clock.now(),
        }
        observation = KnowledgeObservation(
            **fields,
            observation_digest=self._ds.compute("knowledge_observation_digest", fields),
        )
        return self._knowledge.record_observation(observation)
