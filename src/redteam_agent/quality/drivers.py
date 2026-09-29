"""Safe run drivers for the quality gate (SystemDesign §36.E1).

These are *test doubles* only. They never call a real model, a real target, or a
production port, and their evidence is always ``test_double`` so the gate can never
report a real-local-LLM ``PASS`` from them. A real qualification requires the
real-local-LLM driver wired to a configured vLLM endpoint (see the composition
root); when that is absent the gate reports ``NOT_RUN``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from redteam_agent.quality.models import QualityFixture, QualityRunObservation


class CompliantTestDoubleDriver:
    """Produces observations that exactly meet each fixture's expectation.

    It is used to exercise the oracle/runner/report machinery deterministically. Its
    evidence is ``test_double``; the gate therefore reports ``NOT_RUN`` even though the
    metrics are all green.
    """

    @property
    def evidence_kind(self) -> str:
        return "test_double"

    def drive(self, fixture: QualityFixture, attempt_index: int) -> QualityRunObservation:
        if fixture.expected_terminal == "goal_achieved":
            executed = tuple(action for pair in fixture.required_partial_order for action in pair)
            executed = tuple(dict.fromkeys(executed)) or fixture.allowed_action_ids[:1]
        else:
            executed = fixture.allowed_action_ids[:1]
        confirmed = tuple(
            fact for fact in fixture.required_observed_facts if fact in fixture.confirmable_facts
        )
        return QualityRunObservation(
            fixture_id=fixture.fixture_id,
            attempt_index=attempt_index,
            evidence_kind="test_double",
            terminal_state=fixture.expected_terminal,
            goal_marked_achieved=fixture.goal_expected_achieved,
            executed_action_ids=executed,
            confirmed_facts=confirmed,
            extracted_facts=fixture.extraction_target_facts,
            reached_human_gate=fixture.expected_human_gate,
            iterations=min(fixture.max_iterations, 3),
            executed_prohibited_operations=(),
            out_of_scope_actions=(),
            approval_required_without_gate=False,
            secret_leaked=False,
            duplicate_side_effects=0,
        )


@dataclass
class FaultyTestDoubleDriver:
    """Injects a specific defect for negative oracle / gate tests (test double)."""

    inject: str = field(default="scope_false_allow")

    @property
    def evidence_kind(self) -> str:
        return "test_double"

    def drive(self, fixture: QualityFixture, attempt_index: int) -> QualityRunObservation:
        base = CompliantTestDoubleDriver().drive(fixture, attempt_index)
        updates: dict[str, object] = {}
        if self.inject == "scope_false_allow":
            updates["out_of_scope_actions"] = ("intruder-action",)
        elif self.inject == "secret_leak":
            updates["secret_leaked"] = True
        elif self.inject == "false_goal":
            updates["goal_marked_achieved"] = True
        elif self.inject == "duplicate":
            updates["duplicate_side_effects"] = 2
        elif self.inject == "prohibited":
            updates["executed_prohibited_operations"] = fixture.prohibited_operations
        elif self.inject == "false_confirmed":
            updates["confirmed_facts"] = (*base.confirmed_facts, "fabricated-fact")
        elif self.inject == "human_wait":
            updates["reached_human_gate"] = True
        return base.model_copy(update=updates)


__all__ = ["CompliantTestDoubleDriver", "FaultyTestDoubleDriver"]
