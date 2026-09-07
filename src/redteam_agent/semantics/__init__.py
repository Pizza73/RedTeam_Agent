"""Implemented Phase 0A goal semantics (SystemDesign §16.2/§24).

The catalog stores an executable static-rule object with its concrete proof
model and source capability. Non-empty identifier strings alone never make a
condition supported. This is immutable process wiring, not persistent state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field

from redteam_agent.errors import MissionValidationError
from redteam_agent.mission.models import ActiveSessionSelector, ExactSessionSelector, SessionExistsCondition
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.session.models import SessionSecurityContextSnapshot

SESSION_EXISTS_RULE_ID = "goal-rule:session-exists-v1"
SESSION_GOAL_SOURCE_CAPABILITY_ID = "session-manager-current-active-v1"
SEMANTIC_CATALOG_REVISION = "semantic-catalog-v1"


class SessionStateProof(StrictImmutableBoundaryModel):
    """Closed proof shape required by the registered session-exists rule."""

    source_type: Literal["session"] = "session"
    source_id: str = Field(min_length=1)
    source_revision: str = Field(min_length=1)
    observed_at: datetime
    verification_state: Literal["confirmed", "contradicted", "unavailable"]
    active: bool


@runtime_checkable
class SessionGoalSource(Protocol):
    """Source capability required by ``SessionExistsGoalRule``."""

    capability_id: str

    def get_current_session(self, session_id: str) -> SessionSecurityContextSnapshot | None: ...

    def list_current_sessions(self) -> tuple[SessionSecurityContextSnapshot, ...]: ...


class SessionSnapshotReader(Protocol):
    def get(self, session_id: str) -> SessionSecurityContextSnapshot | None: ...

    def all_snapshots(self) -> dict[str, SessionSecurityContextSnapshot]: ...


class EmptySessionGoalSource:
    """Concrete empty source used by isolated validation tests."""

    capability_id = "session-manager-current-active-v1"

    def get_current_session(self, session_id: str) -> SessionSecurityContextSnapshot | None:
        del session_id
        return None

    def list_current_sessions(self) -> tuple[SessionSecurityContextSnapshot, ...]:
        return ()


class RepositorySessionGoalSource:
    """Adapter from the trusted Session repository to the goal source contract."""

    capability_id = "session-manager-current-active-v1"

    def __init__(self, repository: SessionSnapshotReader) -> None:
        self._repository = repository

    def get_current_session(self, session_id: str) -> SessionSecurityContextSnapshot | None:
        return self._repository.get(session_id)

    def list_current_sessions(self) -> tuple[SessionSecurityContextSnapshot, ...]:
        snapshots = self._repository.all_snapshots()
        return tuple(snapshots[key] for key in sorted(snapshots))


@dataclass(frozen=True)
class SemanticCatalog:
    catalog_revision: str
    session_exists_rule: SessionExistsGoalRule | None
    registered_session_refs: frozenset[str] = frozenset()
    registered_host_refs: frozenset[str] = frozenset()
    registered_principal_refs: frozenset[str] = frozenset()
    registered_provider_ids: frozenset[str] = frozenset()
    registered_ad_group_sids: frozenset[str] = frozenset()


@dataclass(frozen=True)
class SessionExistsGoalRule:
    """Concrete static validator and its proof/source bindings."""

    source: SessionGoalSource
    rule_id: Literal["goal-rule:session-exists-v1"] = "goal-rule:session-exists-v1"
    source_capability_id: Literal["session-manager-current-active-v1"] = (
        "session-manager-current-active-v1"
    )
    proof_schema: type[SessionStateProof] = SessionStateProof

    def validate_static(self, condition: SessionExistsCondition, catalog: SemanticCatalog) -> None:
        selector = condition.session_selector
        if isinstance(selector, ExactSessionSelector):
            if selector.session_ref not in catalog.registered_session_refs:
                raise MissionValidationError("session condition references an unregistered session")
        elif isinstance(selector, ActiveSessionSelector):
            if selector.host_ref not in catalog.registered_host_refs:
                raise MissionValidationError("session condition references an unregistered host")
            if (
                selector.principal_ref is not None
                and selector.principal_ref not in catalog.registered_principal_refs
            ):
                raise MissionValidationError("session condition references an unregistered principal")
            if selector.provider_id is not None and selector.provider_id not in catalog.registered_provider_ids:
                raise MissionValidationError("session condition references an unregistered provider")
        else:  # pragma: no cover - discriminated union is exhaustive
            raise MissionValidationError("unsupported session selector")


def default_semantic_catalog(source: SessionGoalSource | None = None) -> SemanticCatalog:
    resolved_source = source if source is not None else EmptySessionGoalSource()
    return SemanticCatalog(
        catalog_revision=SEMANTIC_CATALOG_REVISION,
        session_exists_rule=SessionExistsGoalRule(source=resolved_source),
        registered_session_refs=frozenset({"sess-1"}),
        registered_host_refs=frozenset({"host-1"}),
        registered_principal_refs=frozenset({"user", "root"}),
        registered_provider_ids=frozenset({"c2-main"}),
        registered_ad_group_sids=frozenset({"S-1-5-21-512"}),
    )
