"""Agent quality policy (agent-quality-policy-v2) — the Phase 2 real-LLM quality gate.

Schema capability (SystemDesign §6.2) and agent judgement / extraction quality
(SystemDesign §36.E1 / §37.1 D11 / AI control §11) are separate gates. This package
holds the versioned quality corpus, a deterministic independent oracle, a fixed
300-run runner, and a report whose gate status is ``PASS`` only with real-local-LLM
evidence and all thresholds met; otherwise it is ``NOT_RUN`` / ``BLOCKED`` / ``FAIL``
and never a fabricated pass.
"""

from __future__ import annotations

from redteam_agent.quality.models import (
    AgentQualityCorpus,
    QualityFamily,
    QualityFixture,
    QualityReport,
    QualityRunObservation,
    RunVerdict,
)

__all__ = [
    "AgentQualityCorpus",
    "QualityFamily",
    "QualityFixture",
    "QualityReport",
    "QualityRunObservation",
    "RunVerdict",
]
