"""Deterministic Phase 1 Planner/Analyzer doubles used by integration gates."""

from __future__ import annotations

from redteam_agent.agent.models import PlannerContextEnvelope
from redteam_agent.knowledge.models import AnalyzerCandidateObservation
from redteam_agent.plan.models import PlannerOutput


class MockPlanner:
    def __init__(self, output: PlannerOutput) -> None:
        self._output = output
        self.call_count = 0

    def invoke(self, envelope: PlannerContextEnvelope) -> PlannerOutput:
        del envelope
        self.call_count += 1
        return self._output


class MockAnalyzer:
    def __init__(self, output: AnalyzerCandidateObservation) -> None:
        self._output = output
        self.call_count = 0

    def invoke(self, *, execution_id: str) -> AnalyzerCandidateObservation:
        if execution_id != self._output.source_execution_id:
            raise ValueError("mock Analyzer execution binding mismatch")
        self.call_count += 1
        return self._output
