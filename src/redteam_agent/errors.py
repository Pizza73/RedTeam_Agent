"""Typed errors used at Phase 0A trust and authorization boundaries."""

from __future__ import annotations


class RedTeamAgentError(Exception):
    """Base class for errors that callers may handle by type."""


class PydanticBoundaryValidationError(RedTeamAgentError):
    pass


class MissionValidationError(RedTeamAgentError):
    pass


class MissionStateVersionConflictError(RedTeamAgentError):
    pass


class ContextSelectionError(RedTeamAgentError):
    pass


class ContextAuthorizationError(RedTeamAgentError):
    pass


class DataAccessDeniedError(RedTeamAgentError):
    pass


class SessionContextGrantStaleError(RedTeamAgentError):
    pass


class AvailableToolSnapshotStaleError(RedTeamAgentError):
    pass


class PolicyDecisionStaleError(RedTeamAgentError):
    pass


class AuthorizationEpochMismatchError(RedTeamAgentError):
    pass


class MissionTTLExceededError(RedTeamAgentError):
    pass


class DigestIntegrityError(RedTeamAgentError):
    pass


class ApprovalBindingError(RedTeamAgentError):
    pass


class TargetExtractorResolutionError(RedTeamAgentError):
    pass


class RepositoryConflictError(RedTeamAgentError):
    pass


class BoundaryJsonParseError(PydanticBoundaryValidationError):
    """Untrusted JSON was not a duplicate-free canonical-compatible value."""


class MissionLifecycleAuthorizationError(MissionValidationError):
    """A caller attempted a lifecycle change outside MissionManager policy."""


class UnsupportedGoalIdentifierError(MissionValidationError):
    """A mission referenced an identifier absent from a trusted goal registry."""


class PolicyDecisionProvenanceError(RedTeamAgentError):
    """A decision did not originate from the trusted policy issuance service."""


class PolicyDecisionCompletenessError(RedTeamAgentError):
    """A stored decision is not the complete result of current policy evaluation."""


class ScopeEndpointMismatchError(RedTeamAgentError):
    """Endpoint metadata required for a network scope decision was unavailable."""


class ExecutionSessionScopeError(RedTeamAgentError):
    """The execution session is absent, stale, ineligible, or out of scope."""


class ApprovalPresentationMismatchError(ApprovalBindingError):
    """The human-visible approval intent differs from the execution intent."""


class CurrentAuthorizationStateError(RedTeamAgentError):
    """Current trusted authorization inputs could not be resolved consistently."""


class SandboxRuntimeBindingError(RedTeamAgentError):
    """Sandbox capabilities belong to a different execution runtime."""
