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


class ParameterSchemaError(AuthorizationKernelError):
    """A tool's parameter schema is unsupported, or arguments do not satisfy it."""


class ActionContractError(AuthorizationKernelError):
    """An action contract or its referenced rules are missing or inconsistent."""


class MissionAuthorizationError(AuthorizationKernelError):
    """A mission lifecycle actor is unauthenticated or lacks the required role."""


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


# --- Phase 0B: execution safety -------------------------------------------


class ExecutionStateConflictError(AuthorizationKernelError):
    """Optimistic concurrency control detected a stale execution_state_version."""


class ExecutionUniquenessError(AuthorizationKernelError):
    """A database uniqueness invariant was violated (one decision -> one execution,
    or more than one unconsumed dispatch claim for an execution)."""


class ExecutionRecordError(AuthorizationKernelError):
    """An execution record or its bindings are missing or inconsistent."""


class DispatchClaimError(AuthorizationKernelError):
    """A dispatch claim is missing, in the wrong state, expired, or field-inconsistent."""


class SecretInjectionError(AuthorizationKernelError):
    """A just-in-time secret injection precondition failed (fail closed, no dispatch)."""


class EncryptionKeyUnavailableError(AuthorizationKernelError):
    """A secret version's key/plaintext is unavailable, revoked, or mismatched."""


class ResultCollectionError(AuthorizationKernelError):
    """A result-collection authority/lease/sink precondition failed."""


class ResultTaskBindingError(AuthorizationKernelError):
    """A result task binding is invalid, unknown-mode, or would mutate a fixed mapping."""


class ResultIngestionError(AuthorizationKernelError):
    """A result-ingestion state transition or retry precondition failed."""


class ExecutionRecoveryAuthorityError(AuthorizationKernelError):
    """An execution recovery authority is out of state/window or wrongly bound."""


class CancelAttemptError(AuthorizationKernelError):
    """A cancel attempt precondition (single-consume, binding, state) failed."""


class MissionExecutionBudgetError(AuthorizationKernelError):
    """A durable mission execution budget was exhausted or double-counted."""


class MissionRevisionConflictError(AuthorizationKernelError):
    """A run_id/thread_id did not match the mission id/revision it claims."""
