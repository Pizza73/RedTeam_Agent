"""Typed, fail-closed errors for the authorization kernel.

Every safety-relevant failure raises a specific subclass of
:class:`AuthorizationKernelError`. The kernel never falls back to ALLOW on
error; callers must treat any of these as a hard stop (Default Deny).
"""

from __future__ import annotations


class AuthorizationKernelError(Exception):
    """Base class for all fail-closed kernel errors."""


# --- Boundary / integrity -------------------------------------------------


class PydanticBoundaryValidationError(AuthorizationKernelError):
    """A trust-boundary model rejected unknown fields or coercion."""


class DuplicateJsonKeyError(AuthorizationKernelError):
    """A JSON object at the trust boundary contained a duplicate key."""


class CanonicalJsonError(AuthorizationKernelError):
    """A value could not be canonicalized deterministically."""


class DigestCatalogError(AuthorizationKernelError):
    """A digest definition is missing, duplicated, or otherwise invalid."""


class DigestIntegrityError(AuthorizationKernelError):
    """A stored/loaded object's recomputed digest did not match."""


class RepositoryIntegrityError(AuthorizationKernelError):
    """A repository write/read integrity or binding check failed."""


# --- Mission --------------------------------------------------------------


class MissionValidationError(AuthorizationKernelError):
    """A mission failed validation and cannot become VALIDATED."""


class MissionStateVersionConflictError(AuthorizationKernelError):
    """Optimistic concurrency control detected a stale mission_state_version."""


class MissionLifecycleError(AuthorizationKernelError):
    """An illegal lifecycle transition was attempted."""


# --- Scope / policy -------------------------------------------------------


class ScopeEvaluationError(AuthorizationKernelError):
    """A scope rule or target could not be interpreted (Default Deny)."""


class DataAccessPatternError(AuthorizationKernelError):
    """A resource pattern could not be interpreted (Default Deny)."""


class PolicyEvaluationIndeterminateError(AuthorizationKernelError):
    """Risk/authorization could not be resolved deterministically."""


class PolicyRevisionError(AuthorizationKernelError):
    """A versioned policy artifact failed digest/consistency validation."""


class AuthorizationTtlError(AuthorizationKernelError):
    """A short-lived authorization TTL violated a mission/parent bound."""


class DataAccessResourceError(AuthorizationKernelError):
    """A data-access resource could not be resolved from the source of truth."""


class ApprovalAuthorityError(AuthorizationKernelError):
    """An approval actor is unauthenticated or lacks the mission approver role."""


# --- Tools ----------------------------------------------------------------


class ToolRegistryValidationError(AuthorizationKernelError):
    """A tool definition or registry revision is invalid."""


class TargetExtractorResolutionError(AuthorizationKernelError):
    """A target extractor id is unregistered or extraction failed."""


class SecretArgumentBindingError(AuthorizationKernelError):
    """A secret argument JSON Pointer path is invalid or ambiguous."""


class AvailableToolSnapshotStaleError(AuthorizationKernelError):
    """An AvailableToolSnapshot is stale relative to current bindings."""


class SandboxCapabilityStaleError(AuthorizationKernelError):
    """Sandbox capability digest changed after snapshot issuance."""


# --- Context --------------------------------------------------------------


class ContextSelectionError(AuthorizationKernelError):
    """Context selection failed; no full-text fallback is permitted."""


class SessionContextGrantStaleError(AuthorizationKernelError):
    """A session security context changed after grant issuance."""


# --- Approval / executor --------------------------------------------------


class ApprovalBindingError(AuthorizationKernelError):
    """An approval request/record failed binding verification."""


class MisleadingApprovalPresentationError(AuthorizationKernelError):
    """An approval presentation did not exactly match the executable intent."""


class ExecutorAuthorizationError(AuthorizationKernelError):
    """The executor authorization gate refused to authorize an execution."""
