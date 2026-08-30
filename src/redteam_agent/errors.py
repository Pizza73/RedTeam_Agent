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


class ExecutionAuthorizationError(RedTeamAgentError):
    """A PolicyDecision is not currently executable."""


class DuplicateExecutionError(RedTeamAgentError):
    """A second ExecutionRecord was attempted for one PolicyDecision."""


class ExecutionStateTransitionError(RedTeamAgentError):
    """An execution state transition was stale, invalid, or incomplete."""


class PreDispatchBlockedError(RedTeamAgentError):
    """Current security state blocked execution before any provider call."""


class ExternalDispatchOutcomeUnknownError(RedTeamAgentError):
    """Dispatch may have occurred and must be reconciled without resubmission."""


class AdapterDispatchUncertainError(RedTeamAgentError):
    """An adapter could not confirm whether the external submit was accepted."""


class AdapterOperationError(RedTeamAgentError):
    """A mock adapter operation failed without exposing untrusted provider content."""


class AdapterResolutionError(RedTeamAgentError):
    """A trusted registry could not resolve the adapter bound by authorization."""


class TrustedDependencyUnavailableError(RedTeamAgentError):
    """A mandatory trusted runtime dependency was absent."""


class ResultIngestionError(RedTeamAgentError):
    """Result ingestion could not safely complete."""


class RawResultStreamingError(ResultIngestionError):
    """Streaming or quarantine commit failed and requires recovery."""


class RawResultQuarantineError(ResultIngestionError):
    """Raw result quarantine metadata or commit failed closed."""


class WorkflowRunBindingError(RedTeamAgentError):
    """A run_id/thread_id did not bind to the current Mission revision."""


class ResultIngestionLeaseError(ResultIngestionError):
    """A result-ingestion lease is still active, absent, or not safely recoverable."""
