"""Current-source goal evaluator; saved evaluations never become authority."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Literal

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import GoalEvaluationConflictError, GoalEvaluationError
from redteam_agent.goal.models import (
    ConditionEvaluation,
    EvidenceReference,
    GoalEvaluationRecord,
    GoalStatus,
)
from redteam_agent.knowledge.service import KnowledgeService
from redteam_agent.mission.models import (
    ActiveSessionSelector,
    ADPrincipalContextCondition,
    ExactSessionSelector,
    SessionExistsCondition,
)
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork
from redteam_agent.storage.repositories import SessionSecurityContextSnapshotRepository

_EVALUATION_NS = "goal_evaluation"


class GoalEvaluationService:
    def __init__(
        self, *, database: Database, digest_service: DigestService, clock: Clock,
        context_resolver: AuthorizationContextResolver,
        session_repository: SessionSecurityContextSnapshotRepository,
        knowledge_service: KnowledgeService,
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._clock = clock
        self._resolver = context_resolver
        self._sessions = session_repository
        self._knowledge = knowledge_service

    def evaluate(self, *, mission_id: str) -> GoalEvaluationRecord:
        now = self._clock.now()
        mission = self._resolver.resolve(mission_id, now=now).mission
        head = self._knowledge.verify_current_head(mission_id)
        if head.mission_revision != mission.mission_revision:
            raise GoalEvaluationError("Knowledge head is stale for the current mission revision")
        source_snapshot_digest = self._source_snapshot_digest()
        evaluations = tuple(self._evaluate_condition(item, now=now) for item in mission.success_conditions)
        status = _aggregate(evaluations, mission.success_mode)
        status_payload = status.model_dump(mode="python")
        fields = {
            "mission_id": mission_id, "mission_revision": mission.mission_revision,
            "authorization_epoch": mission.authorization_epoch,
            "mission_state_version": mission.mission_state_version,
            "knowledge_head_id": head.head_id, "knowledge_head_digest": head.head_digest,
            "source_snapshot_digest": source_snapshot_digest,
            "status": status_payload, "evaluated_at": now,
        }
        digest = self._ds.compute("goal_evaluation_digest", {"evaluation_id": "pending", **fields})
        evaluation_id = f"goal-eval-{digest[:24]}"
        record_fields = {"evaluation_id": evaluation_id, **fields}
        record = GoalEvaluationRecord(
            evaluation_id=evaluation_id, mission_id=mission_id,
            mission_revision=mission.mission_revision, authorization_epoch=mission.authorization_epoch,
            mission_state_version=mission.mission_state_version, knowledge_head_id=head.head_id,
            knowledge_head_digest=head.head_digest, source_snapshot_digest=source_snapshot_digest,
            status=status, evaluated_at=now,
            evaluation_digest=self._ds.compute("goal_evaluation_digest", record_fields),
        )
        current = self._resolver.resolve(mission_id, now=self._clock.now()).mission
        current_head = self._knowledge.verify_current_head(mission_id)
        if (
            current.mission_revision != mission.mission_revision
            or current.authorization_epoch != mission.authorization_epoch
            or current.mission_state_version != mission.mission_state_version
            or current_head.head_digest != head.head_digest
            or self._source_snapshot_digest() != source_snapshot_digest
        ):
            raise GoalEvaluationConflictError("goal source changed during evaluation")
        with UnitOfWork(self._db):
            self._db.occ_insert_idempotent(
                _EVALUATION_NS, evaluation_id, 1,
                json.dumps(record.model_dump(mode="json"), sort_keys=True),
            )
        return record

    def _source_snapshot_digest(self) -> str:
        snapshots = self._sessions.all_snapshots()
        ordered = [
            snapshots[session_id].model_dump(mode="python")
            for session_id in sorted(snapshots)
        ]
        return self._ds.compute("goal_source_snapshot_digest", {"sessions": ordered})

    def get(self, evaluation_id: str) -> GoalEvaluationRecord | None:
        row = self._db.occ_get(_EVALUATION_NS, evaluation_id)
        if row is None:
            return None
        record = GoalEvaluationRecord.model_validate_json(row[1])
        if record.evaluation_id != evaluation_id:
            raise GoalEvaluationError("goal evaluation row identity mismatch")
        payload = record.model_dump(mode="python")
        expected = payload.pop("evaluation_digest")
        self._ds.verify("goal_evaluation_digest", payload, expected)
        return record

    def verify_current(self, evaluation_id: str, *, mission_id: str) -> GoalEvaluationRecord:
        record = self.get(evaluation_id)
        if record is None or record.mission_id != mission_id:
            raise GoalEvaluationError("goal evaluation not found for mission")
        mission = self._resolver.resolve(mission_id, now=self._clock.now()).mission
        head = self._knowledge.verify_current_head(mission_id)
        if (
            record.mission_revision != mission.mission_revision
            or record.authorization_epoch != mission.authorization_epoch
            or record.mission_state_version != mission.mission_state_version
            or record.knowledge_head_id != head.head_id
            or record.knowledge_head_digest != head.head_digest
            or record.source_snapshot_digest != self._source_snapshot_digest()
        ):
            raise GoalEvaluationConflictError("goal evaluation is not current")
        return record

    def _evaluate_session(self, condition: SessionExistsCondition, *, now: datetime) -> ConditionEvaluation:
        selector = condition.session_selector
        if isinstance(selector, ExactSessionSelector):
            snapshot = self._sessions.get(selector.session_ref)
            if snapshot is None:
                return _condition(condition.condition_id, "not_achieved", "CONDITION_ABSENT", ())
            reference = _session_reference(snapshot.session_id, snapshot.observed_at.isoformat(), "confirmed")
            if now >= snapshot.session_fresh_until:
                return _condition(
                    condition.condition_id, "indeterminate", "SESSION_REFRESH_FAILED", (reference,)
                )
            is_active = snapshot.context.security_status == "ok"
            return _condition(
                condition.condition_id,
                "achieved" if is_active else "not_achieved",
                "CONDITION_MATCHED" if is_active else "CONDITION_ABSENT",
                (reference,),
            )
        assert isinstance(selector, ActiveSessionSelector)
        candidates = [
            item for item in self._sessions.all_snapshots().values()
            if item.context.host == selector.host_ref
            and (selector.principal_ref is None or item.context.current_principal == selector.principal_ref)
        ]
        if selector.provider_id is not None:
            return _condition(
                condition.condition_id, "indeterminate", "EVIDENCE_SOURCE_UNAVAILABLE", ()
            )
        fresh = [item for item in candidates if now < item.session_fresh_until]
        active_candidates = [item for item in fresh if item.context.security_status == "ok"]
        if active_candidates:
            chosen = sorted(active_candidates, key=lambda item: item.session_id)[0]
            return _condition(
                condition.condition_id, "achieved", "CONDITION_MATCHED",
                (_session_reference(chosen.session_id, chosen.observed_at.isoformat(), "confirmed"),),
            )
        if candidates and not fresh:
            refs = tuple(
                _session_reference(item.session_id, item.observed_at.isoformat(), "unavailable")
                for item in sorted(candidates, key=lambda item: item.session_id)
            )
            return _condition(condition.condition_id, "indeterminate", "SESSION_REFRESH_FAILED", refs)
        return _condition(condition.condition_id, "not_achieved", "CONDITION_ABSENT", ())

    def _evaluate_condition(
        self, condition: SessionExistsCondition | ADPrincipalContextCondition, *, now: datetime,
    ) -> ConditionEvaluation:
        if isinstance(condition, SessionExistsCondition):
            return self._evaluate_session(condition, now=now)
        base = self._evaluate_session(
            SessionExistsCondition(
                condition_id=condition.condition_id,
                session_selector=condition.session_selector,
            ),
            now=now,
        )
        if base.status != "achieved":
            return base
        source_ids = {item.source_id for item in base.evidence_references}
        sessions = [self._sessions.get(source_id) for source_id in source_ids]
        if any(
            session is not None
            and session.context.current_principal == condition.principal_ref
            and condition.required_group_sid is not None
            and condition.required_group_sid in session.context.verified_ad_group_sids
            for session in sessions
        ):
            return base
        return _condition(
            condition.condition_id, "not_achieved", "CONDITION_ABSENT",
            base.evidence_references,
        )


def _session_reference(
    source_id: str, revision: str,
    state: Literal["confirmed", "contradicted", "unavailable"],
) -> EvidenceReference:
    return EvidenceReference(
        source_type="session", source_id=source_id, source_revision=revision,
        proof_references=(), verification_state=state,
    )


def _condition(
    condition_id: str,
    status: Literal["achieved", "not_achieved", "indeterminate"],
    reason: Literal[
        "CONDITION_MATCHED", "CONDITION_ABSENT", "SESSION_REFRESH_FAILED",
        "EVIDENCE_SOURCE_UNAVAILABLE",
    ],
    evidence: tuple[EvidenceReference, ...],
) -> ConditionEvaluation:
    return ConditionEvaluation(
        condition_id=condition_id, status=status, reason_code=reason,
        evidence_references=evidence,
    )


def _aggregate(evaluations: tuple[ConditionEvaluation, ...], mode: Literal["all", "any"]) -> GoalStatus:
    achieved = tuple(item.condition_id for item in evaluations if item.status == "achieved")
    remaining = tuple(item.condition_id for item in evaluations if item.status == "not_achieved")
    unknown = tuple(item for item in evaluations if item.status == "indeterminate")
    if mode == "all":
        overall: Literal["achieved", "not_achieved", "indeterminate"] = (
            "not_achieved" if remaining else ("indeterminate" if unknown else "achieved")
        )
    else:
        overall = "achieved" if achieved else ("indeterminate" if unknown else "not_achieved")
    evidence = tuple(reference for item in evaluations for reference in item.evidence_references)
    return GoalStatus(
        status=overall, achieved_conditions=achieved, remaining_conditions=remaining,
        indeterminate_conditions=unknown, evidence_references=evidence,
    )
