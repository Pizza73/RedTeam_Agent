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


# --- Phase 0C: data security / audit --------------------------------------


class AggregateConsistencyError(AuthorizationKernelError):
    """An ApplicationUnitOfWork aggregate command was replayed with a different
    input, missed an expected version, or a child repository committed on its own."""


class EncryptionUnavailableError(AuthorizationKernelError):
    """The standard AEAD provider (the ``cryptography`` package / AES-256-GCM) is
    not available or a key/algorithm is unusable. Fail closed; never downgrade to
    plaintext or a non-standard construction (infrastructure/configuration error)."""


class NonceReuseError(AuthorizationKernelError):
    """An encryption nonce would be reused for a key (forbidden)."""


class KeyDomainSeparationError(AuthorizationKernelError):
    """A key domain / resource DEK separation invariant was violated (shared tag,
    shared domain key id across domains, or a shared resource DEK)."""


class CrossDomainKeyError(AuthorizationKernelError):
    """A ciphertext/metadata for one key domain was opened with another domain's key,
    or the AAD domain/resource binding did not match."""


class RawResultQuarantineError(AuthorizationKernelError):
    """An encrypted quarantine write/encrypt/binding/integrity check failed (fail closed)."""


class SecretLifecycleError(AuthorizationKernelError):
    """An append-only secret lifecycle event/head/OCC invariant failed."""


class SecretConfirmationError(AuthorizationKernelError):
    """A secret confirmation/replacement precondition (heads/version/actor) failed."""


class SecretMigrationRequiredError(AuthorizationKernelError):
    """A legacy secret reference could not be migrated one-to-one (ambiguous, missing,
    or digest mismatch); stop rather than aggregate or re-import plaintext."""


class LeaseError(AuthorizationKernelError):
    """A typed lease predicate (owner/fence/epoch/deadline/state/authority) failed."""


class ClockIntegrityError(AuthorizationKernelError):
    """UTC rolled back below the high-water mark, or wall/monotonic divergence exceeded
    the configured bound; stop new authorization, claim, lease and renewal."""


class DeploymentEpochError(AuthorizationKernelError):
    """A deployment epoch mirror is missing, stale, or worker-mutated, or multi-host
    topology was detected."""


class SecureIngestionError(AuthorizationKernelError):
    """A repository-bound secure ingestion / publication precondition failed."""


class OutputPublicationError(AuthorizationKernelError):
    """Output could not be published under the fixed publication rule/parser (not published)."""


class VerifiedErasureError(AuthorizationKernelError):
    """A verified-erasure precondition (intent/claim/evidence/key/inventory/read-back) failed."""


class AuditChainError(AuthorizationKernelError):
    """A mission audit sequence/hash-chain invariant failed (gap, duplicate, tamper)."""


class GenerationWitnessError(AuthorizationKernelError):
    """A TPM-witnessed authenticated generation commit precondition failed."""


class AnchorRecoveryRequiredError(AuthorizationKernelError):
    """The current TPM witness / generation anchor is unavailable, reset, rolled back,
    identity-mismatched, or ambiguous; all missions stop. No local re-seed."""


class CriticalWitnessError(AuthorizationKernelError):
    """A critical state intent is missing, stale, ambiguous, or not yet bound to
    the authenticated TPM generation. No protected continuation may proceed."""


class TrustRecoveryError(AuthorizationKernelError):
    """An offline trust-recovery approval or adopted state failed exact binding,
    freshness, worker-stop, one-time consumption, or read-back verification."""


class ActivationLockError(AuthorizationKernelError):
    """The host activation lock could not be acquired (a second root is running)."""


class ProductionCompositionError(AuthorizationKernelError):
    """The production composition root failed a self-check, detected a test double,
    or was asked to swap a trusted dependency after startup."""


class ArchitectureViolationError(AuthorizationKernelError):
    """A logical component owns a duplicate responsibility or imports in a forbidden
    direction (architecture ownership/import check)."""


class C2AdapterUnavailableError(AuthorizationKernelError):
    """A C2 adapter is not activated because its immutable provider contract,
    connection identity, authentication reference, or isolation gate is incomplete."""


class C2AdapterContractError(AuthorizationKernelError):
    """A provider operation, identifier, or wire shape violated the pinned C2 contract."""


class C2AdapterTransportError(AuthorizationKernelError):
    """A fixed C2 transport failed without exposing response or credential content."""


class C2AdapterQualificationError(AuthorizationKernelError):
    """C2 adapter qualification evidence is incomplete, forged, or not production-grade."""


class MCPAdapterUnavailableError(AuthorizationKernelError):
    """The configured MCP adapter is not qualified for the requested operation."""


class MCPContractError(AuthorizationKernelError):
    """An MCP request, response, tool, or JSON-RPC binding violated the pinned contract."""


class MCPTransportError(AuthorizationKernelError):
    """An MCP transport failed without exposing provider content or credentials."""


class MCPProtocolRevisionMismatchError(MCPContractError):
    """A server does not support the exact configured MCP protocol revision."""


class MCPServerIdentityMismatchError(MCPContractError):
    """Self-reported logical server identity changed from its approved binding."""


class MCPTransportIdentityMismatchError(MCPAdapterUnavailableError):
    """The cryptographic or executable MCP transport identity did not match."""


class MCPTaskCapabilityError(MCPAdapterUnavailableError):
    """MCP Tasks was used without the required server, extension, and client support."""


class RemoteMCPTrustError(MCPAdapterUnavailableError):
    """Remote MCP trust or enforcement capability was missing or stale."""


class SchemaMigrationRequiredError(AuthorizationKernelError):
    """Normal startup found an unknown/missing schema; it must not auto-migrate. An
    explicit stopped-worker migration under the same activation lock is required."""


class KnowledgeStateIntegrityError(AuthorizationKernelError):
    """A Knowledge current head, projection, source binding, or witness is invalid."""


class GoalEvaluationError(AuthorizationKernelError):
    """A goal cannot be evaluated from the current mission and trusted sources."""


class GoalEvaluationConflictError(GoalEvaluationError):
    """A source changed while a goal evaluation was being committed."""


class AgentLoopError(AuthorizationKernelError):
    """The bounded Phase 1 controller or its checkpoint contract was violated."""


class PlannerContextError(AuthorizationKernelError):
    """A planner context envelope or its current-source binding is invalid."""


class PlannerCandidateError(AuthorizationKernelError):
    """An action candidate projection or planner selection is invalid."""


# --- Phase 2: local LLM ---------------------------------------------------


class LLMProfileError(AuthorizationKernelError):
    """A local LLM / mock agent profile is structurally invalid or unregistered."""


class LLMProfileMismatchError(LLMProfileError):
    """A mission's fixed model / wire API / chat template / tokenizer / output mode
    changed mid-mission (fail closed, no implicit switch)."""


class LLMAttestationError(LLMProfileError):
    """The configured local vLLM server could not be attested against the immutable
    profile: metadata missing / ambiguous / name-only, or the served model hash, tokenizer,
    chat template, runtime version, structured-output mode or endpoint binding mismatched."""


class LLMCapabilityError(AuthorizationKernelError):
    """A schema capability result is missing, stale, unbound, or below threshold, or a
    mission's required schema digests are not all covered by a passed capability result."""


class LLMRequestBudgetError(AuthorizationKernelError):
    """A rendered request's token budget (input + reserved output + margin) exceeds the
    profile's max context, is unmeasurable, or a request/output/transport retry budget was
    exhausted; the request must not reach the network."""


class LLMTransportError(AuthorizationKernelError):
    """A local LLM transport outcome is unknown, timed out, was cancelled, or returned a
    non-structured / free-form body; it is not silently retried and never parsed as a proposal.

    ``reason`` is a typed code so evidence about *how* a request ended is exact: a
    connection failure can never be mistaken for a timeout or an in-flight cancellation.
    """

    #: Allowed typed transport-failure reasons.
    REASONS: frozenset[str] = frozenset({
        "timeout",
        "cancelled_before_send",
        "cancelled_in_flight",
        "connect_error",
        "http_status",
        "protocol_error",
        "malformed_response",
        "config_error",
        "unknown",
    })

    def __init__(self, message: str, *, reason: str = "unknown") -> None:
        if reason not in self.REASONS:
            raise ValueError(f"unknown LLM transport reason: {reason}")
        super().__init__(message)
        self.reason = reason


class LLMOutputValidationError(AuthorizationKernelError):
    """A local LLM produced a structured body that failed the strict application boundary.
    This is an output-validation failure (retried within the bounded validation budget),
    content-free so the invalid body / raw validation error never enters a retry prompt or log."""


class LLMEvaluationError(AuthorizationKernelError):
    """A local evaluation / qualification precondition failed: the evaluation entry point
    reached a production port, a corpus was incomplete/rewritten, a denominator was zero, or a
    real-local-LLM gate was claimed without real-model evidence."""
