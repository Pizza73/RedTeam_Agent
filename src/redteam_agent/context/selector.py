"""Deterministic context selector (SystemDesign §18).

The selector reads only index metadata (via a narrow reader protocol) and
produces ranked candidate references. It never reads bodies or secrets and never
falls back to full-text search. Ranking is deterministic for a fixed input and
index revision, and default caps cannot be widened by callers.
"""

from __future__ import annotations

from typing import Protocol

from redteam_agent.context.models import ContextResourceIndexRecord, RankedContextCandidate
from redteam_agent.errors import ContextSelectionError
from redteam_agent.policy.scope_models import (
    HostTargetReference,
    IpTargetReference,
    NamedTargetReference,
    RemoteFilesystemTargetReference,
    SessionTargetReference,
    TargetReference,
)

RANKING_POLICY_VERSION = "context-ranking-v1"
DEFAULT_CANDIDATE_LIMIT = 100
DEFAULT_PER_TYPE_LIMIT = 10


class ContextIndexReader(Protocol):
    def query_by_mission(self, mission_id: str) -> tuple[ContextResourceIndexRecord, ...]: ...


def target_reference_value(reference: TargetReference) -> str:
    if isinstance(reference, IpTargetReference):
        return reference.address
    if isinstance(reference, NamedTargetReference):
        return reference.value
    if isinstance(reference, HostTargetReference):
        return reference.host_id
    if isinstance(reference, SessionTargetReference):
        return reference.session_id
    if isinstance(reference, RemoteFilesystemTargetReference):
        return f"{reference.host_ref}:{reference.path}"
    raise ContextSelectionError("unknown target reference type")


def _observed_ordinal(record: ContextResourceIndexRecord) -> int:
    return int(record.observed_at.timestamp())


class ContextSelector:
    def __init__(
        self,
        reader: ContextIndexReader,
        *,
        candidate_limit: int = DEFAULT_CANDIDATE_LIMIT,
        per_type_limit: int = DEFAULT_PER_TYPE_LIMIT,
    ) -> None:
        if not (0 < candidate_limit <= DEFAULT_CANDIDATE_LIMIT):
            raise ContextSelectionError("candidate limit may only narrow the system maximum")
        if not (0 < per_type_limit <= DEFAULT_PER_TYPE_LIMIT):
            raise ContextSelectionError("per-type limit may only narrow the system maximum")
        self._reader = reader
        self._candidate_limit = candidate_limit
        self._per_type_limit = per_type_limit

    def select(
        self,
        mission_id: str,
        current_target_values: frozenset[str],
    ) -> tuple[RankedContextCandidate, ...]:
        try:
            records = self._reader.query_by_mission(mission_id)
        except Exception as exc:
            raise ContextSelectionError("context index query failed") from exc

        ranked: list[RankedContextCandidate] = []
        for record in records:
            if record.mission_id != mission_id:
                # Index reader must return only this mission's records.
                raise ContextSelectionError("context index returned a cross-mission record")
            target_match = any(
                target_reference_value(reference) in current_target_values
                for reference in record.target_references
            )
            reasons = ("TARGET_MATCH",) if target_match else ("MISSION_SCOPED",)
            rank_vector = (0 if target_match else 1, -_observed_ordinal(record))
            ranked.append(
                RankedContextCandidate(
                    candidate=record.to_candidate(),
                    selection_reason_codes=reasons,
                    rank_vector=rank_vector,
                    stable_tiebreaker=record.resource_id,
                    ranking_policy_version=RANKING_POLICY_VERSION,
                )
            )

        ranked.sort(key=lambda item: (item.rank_vector, item.stable_tiebreaker))
        return self._apply_caps(ranked)

    def _apply_caps(
        self, ranked: list[RankedContextCandidate]
    ) -> tuple[RankedContextCandidate, ...]:
        per_type: dict[str, int] = {}
        capped: list[RankedContextCandidate] = []
        for item in ranked:
            resource_type = item.candidate.resource_type
            if per_type.get(resource_type, 0) >= self._per_type_limit:
                continue
            per_type[resource_type] = per_type.get(resource_type, 0) + 1
            capped.append(item)
            if len(capped) >= self._candidate_limit:
                break
        return tuple(capped)
