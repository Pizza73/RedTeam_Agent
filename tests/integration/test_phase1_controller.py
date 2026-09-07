"""Phase 1 foundation: witnessed Knowledge, three-valued goal and controller."""

from __future__ import annotations

import support
import support_phase0b as p0b
import support_phase0c as p0c
from redteam_agent.composition.phase1 import build_phase1_kernel
from redteam_agent.knowledge.models import KnowledgeObservation


def _running_phase1():
    kernel = build_phase1_kernel(phase0c=p0c.make_phase0c())
    seeded = p0b.seed_authorized(kernel.phase0c.phase0b)
    head = kernel.knowledge_service.initialize_mission(
        mission_id=seeded.seeded.revision.mission_id,
        mission_revision=seeded.seeded.revision.mission_revision,
        recorded_at=support.T0,
    )
    return kernel, seeded, head


def test_goal_controller_plans_then_finalizes_from_current_session_source() -> None:
    kernel, seeded, _head = _running_phase1()
    mission_id = seeded.seeded.revision.mission_id

    first = kernel.controller.step(
        mission_id=mission_id, operation_id="loop-1", candidate_ids=("candidate-scan",)
    )
    assert first.action == "PLAN" and first.reason_code == "CANDIDATES_READY"
    assert first.goal_evaluation_id is not None

    kernel.phase0c.phase0b.phase0a.session_repository.save(support.session_snapshot())
    second = kernel.controller.step(mission_id=mission_id, operation_id="loop-2")
    assert second.action == "FINALIZE" and second.reason_code == "GOAL_ACHIEVED"

    checkpoint = kernel.controller.checkpoint(mission_id)
    assert checkpoint is not None
    assert checkpoint.goal_evaluation_id == second.goal_evaluation_id
    assert not hasattr(checkpoint, "mission")
    assert not hasattr(checkpoint, "goal_status")
    assert not hasattr(checkpoint, "context_body")


def test_unconfirmed_observation_does_not_change_goal_or_witnessed_fact_head() -> None:
    kernel, seeded, head = _running_phase1()
    mission_id = seeded.seeded.revision.mission_id
    fields = {
        "observation_id": "observation-1", "mission_id": mission_id,
        "source_execution_id": "execution-1", "observation_type": "finding",
        "subject_ref": "host-1", "predicate": "session_exists", "object_ref": "sess-fake",
        "attributes": {"claim": "root session exists"}, "source_artifact_ids": (),
        "llm_confidence": 1.0, "observed_at": support.T0,
    }
    observation = KnowledgeObservation(
        **fields,
        observation_digest=kernel.phase0c.phase0b.phase0a.digest_service.compute(
            "knowledge_observation_digest", fields
        ),
    )
    kernel.knowledge_service.record_observation(observation)
    evaluation = kernel.goal_service.evaluate(mission_id=mission_id)
    assert evaluation.status.status == "not_achieved"
    assert kernel.knowledge_service.current_head(mission_id) == head


def test_controller_prioritizes_existing_execution_before_goal_or_planning() -> None:
    kernel, seeded, _head = _running_phase1()
    decision = kernel.controller.step(
        mission_id=seeded.seeded.revision.mission_id,
        operation_id="loop-recovery", active_execution_id="execution-pending",
        candidate_ids=("candidate-new",),
    )
    assert decision.action == "RECOVER"
    assert decision.goal_evaluation_id is None
