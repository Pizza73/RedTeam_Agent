"""Phase 1 Knowledge fail-closed checks."""

from __future__ import annotations

import json

import pytest

import support
import support_phase0b as p0b
import support_phase0c as p0c
from redteam_agent.agent.models import ActionCandidateSeed
from redteam_agent.composition.phase1 import build_phase1_kernel
from redteam_agent.errors import (
    GoalEvaluationConflictError,
    KnowledgeStateIntegrityError,
    PlannerCandidateError,
    RepositoryIntegrityError,
)
from redteam_agent.policy.scope_models import IpTargetReference


def test_missing_explicit_knowledge_head_fails_goal_evaluation() -> None:
    kernel = build_phase1_kernel(phase0c=p0c.make_phase0c())
    seeded = p0b.seed_authorized(kernel.phase0c.phase0b)
    with pytest.raises(KnowledgeStateIntegrityError):
        kernel.goal_service.evaluate(mission_id=seeded.seeded.revision.mission_id)


def test_knowledge_head_tamper_is_rejected_and_not_treated_as_empty() -> None:
    kernel = build_phase1_kernel(phase0c=p0c.make_phase0c())
    seeded = p0b.seed_authorized(kernel.phase0c.phase0b)
    mission_id = seeded.seeded.revision.mission_id
    kernel.knowledge_service.initialize_mission(
        mission_id=mission_id, mission_revision=1, recorded_at=support.T0
    )
    db = kernel.phase0c.phase0b.phase0a.database
    row = db.occ_get("knowledge_security_head", mission_id)
    assert row is not None
    payload = json.loads(row[1])
    payload["fact_state_root_digest"] = "0" * 64
    db.connection.execute(
        "UPDATE occ_store SET json = ? WHERE namespace = ? AND key = ?",
        (json.dumps(payload, sort_keys=True), "knowledge_security_head", mission_id),
    )
    db.connection.commit()
    with pytest.raises((KnowledgeStateIntegrityError, RepositoryIntegrityError)):
        kernel.goal_service.evaluate(mission_id=mission_id)


def test_session_source_change_during_goal_evaluation_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = build_phase1_kernel(phase0c=p0c.make_phase0c())
    seeded = p0b.seed_authorized(kernel.phase0c.phase0b)
    mission_id = seeded.seeded.revision.mission_id
    kernel.knowledge_service.initialize_mission(
        mission_id=mission_id, mission_revision=1, recorded_at=support.T0
    )
    original = kernel.goal_service._evaluate_session

    def change_source(condition, *, now):
        result = original(condition, now=now)
        kernel.phase0c.phase0b.phase0a.session_repository.save(support.session_snapshot())
        return result

    monkeypatch.setattr(kernel.goal_service, "_evaluate_session", change_source)
    with pytest.raises(GoalEvaluationConflictError):
        kernel.goal_service.evaluate(mission_id=mission_id)


def test_candidate_id_is_rederived_even_if_projection_digest_is_recomputed() -> None:
    kernel = build_phase1_kernel(phase0c=p0c.make_phase0c())
    seeded = p0b.seed_authorized(kernel.phase0c.phase0b)
    projection = kernel.candidate_projector.build(
        snapshot_id=seeded.seeded.snapshot.snapshot_id,
        seeds=(ActionCandidateSeed(
            tool_ref=seeded.seeded.tool.tool_ref,
            canonical_target_binding=(IpTargetReference(type="ip", address="10.1.2.3"),),
            satisfied_precondition_refs=(), objective_dependency_ids=(),
        ),),
        source_version_digests=("source-v1",),
    )
    forged_candidate = projection.candidates[0].model_copy(update={"candidate_id": "candidate-forged"})
    forged_fields = projection.model_dump(mode="python")
    forged_fields["candidates"] = [forged_candidate.model_dump(mode="python")]
    forged_fields.pop("projection_digest")
    forged = projection.model_copy(update={
        "candidates": (forged_candidate,),
        "projection_digest": kernel.phase0c.phase0b.phase0a.digest_service.compute(
            "action_candidate_digest", forged_fields
        ),
    })
    with pytest.raises(PlannerCandidateError):
        kernel.candidate_projector.verify(forged, snapshot=seeded.seeded.snapshot)
