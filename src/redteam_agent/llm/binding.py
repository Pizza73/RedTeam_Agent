"""Current mission binding check for Local LLM attempts (SystemDesign §6.3 / §7).

Before each real model attempt the gateway calls this checker (through the adapter's
``before_attempt`` hook). It re-resolves the current mission and fails closed if the
mission is not RUNNING, or if the fixed mission revision, authorization epoch or LLM
profile digest changed mid-mission (an implicit model / wire API / template / tokenizer
/ output-mode change is an ``LLMProfileMismatchError``, never an implicit switch).
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from redteam_agent.errors import LLMProfileMismatchError
from redteam_agent.llm.adapters import CurrentBindingChecker
from redteam_agent.runtime.authorization_context import CurrentAuthorizationRuntimeContext
from redteam_agent.runtime.clock import Clock


class MissionContextResolver(Protocol):
    """Resolves the current, integrity-verified authorization context for a mission."""

    def resolve(self, mission_id: str, *, now: datetime) -> CurrentAuthorizationRuntimeContext:
        ...


class MissionBindingChecker(CurrentBindingChecker):
    def __init__(
        self,
        *,
        context_resolver: MissionContextResolver,
        clock: Clock,
        mission_id: str,
        expected_profile_digest: str,
        expected_revision: int,
        expected_epoch: int,
    ) -> None:
        self._resolver = context_resolver
        self._clock = clock
        self._mission_id = mission_id
        self._expected_profile_digest = expected_profile_digest
        self._expected_revision = expected_revision
        self._expected_epoch = expected_epoch

    def check(self) -> None:
        context = self._resolver.resolve(self._mission_id, now=self._clock.now())
        mission = context.mission
        if mission.state != "RUNNING":
            raise LLMProfileMismatchError("mission is not RUNNING for a model attempt")
        if mission.mission_revision != self._expected_revision:
            raise LLMProfileMismatchError("mission revision changed mid-mission")
        if mission.authorization_epoch != self._expected_epoch:
            raise LLMProfileMismatchError("authorization epoch changed mid-mission")
        if mission.llm_profile_digest != self._expected_profile_digest:
            raise LLMProfileMismatchError("bound LLM profile digest changed mid-mission")


__all__ = ["MissionBindingChecker", "MissionContextResolver"]
