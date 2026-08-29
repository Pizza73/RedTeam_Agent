"""Select candidate resource references from metadata only."""

from __future__ import annotations

from redteam_agent.canonical import canonicalize
from redteam_agent.errors import ContextSelectionError
from redteam_agent.models.context import (
    CandidateContextResource,
    ContextResourceIndexRecord,
    ContextSelectionRequest,
)
from redteam_agent.repositories.context import ContextResourceIndexRepository


class ContextSelector:
    """This service has no API capable of loading resource bodies or secret values."""

    def __init__(self, index_repository: ContextResourceIndexRepository) -> None:
        self.index_repository = index_repository

    def select(self, request: ContextSelectionRequest) -> tuple[CandidateContextResource, ...]:
        try:
            records = self.index_repository.list_for_mission(request.mission_id)
        except Exception as exc:
            raise ContextSelectionError("unable to query context metadata index") from exc
        selected = [record for record in records if self._relevant(record, request)]
        selected.sort(
            key=lambda item: (
                item.binding.resource_id,
                item.binding.resource_version,
                item.binding.resource_digest,
            )
        )
        return tuple(
            CandidateContextResource(
                binding=record.binding,
                resource_type=record.resource_type,
                verification_state=record.verification_state,
                classification=record.classification,
                source_index_id=record.index_id,
            )
            for record in selected
        )

    @staticmethod
    def _relevant(record: ContextResourceIndexRecord, request: ContextSelectionRequest) -> bool:
        if record.verification_state in {"contradicted", "unavailable"}:
            return False
        if not request.current_targets:
            return True
        requested = {
            canonicalize(target.model_dump(mode="python")) for target in request.current_targets
        }
        indexed = {
            canonicalize(target.model_dump(mode="python")) for target in record.target_references
        }
        return bool(requested & indexed)

