"""Agent model profile records (SystemDesign §7 / §21).

The agent model profile is a strict, immutable discriminated union keyed on
``profile_type``:

* :class:`MockAgentProfile` (``profile_type="mock"``) — the deterministic
  Phase 0A-1 double. It never calls a real model and must never be used to
  bypass the Phase 2 capability check on a real-LLM mission.
* :class:`LocalLLMProfile` (``profile_type="vllm"``) — a version-managed local
  vLLM profile pinning wire API, structured-output mode, tool-output support,
  system-message handling, context/output token limits, model name/hash,
  tokenizer revision and an optional chat-template digest.

``profile_digest`` is computed over the canonical profile *excluding the digest
field itself*, so a forged profile fails integrity verification on load. A
:class:`LocalLLMProfile`'s fitness for a real mission is *not* self-attested;
it requires a passed :class:`~redteam_agent.llm.capability.LLMSchemaCapabilityResult`
bound to this ``profile_digest`` (verified by the capability service), so a bare
boolean can never authorize a real model.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, model_validator

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.json_boundary import parse_json_no_duplicate_keys
from redteam_agent.errors import PydanticBoundaryValidationError
from redteam_agent.models.base import StrictImmutableBoundaryModel

# --- Versioned allowlists (SystemDesign §7) -------------------------------

WIRE_API = "chat_completions"

STRUCTURED_OUTPUT_MODE_ALLOWLIST_REVISION = "structured-output-mode-allowlist-v1"
# Native JSON-schema-constrained decoding is the first choice; the tool-output
# JSON mode is the only permitted fallback and only when the capability check
# confirmed native decoding does not work (SystemDesign §6.1 / §6.2).
STRUCTURED_OUTPUT_MODES: frozenset[str] = frozenset({"native_json_schema", "tool_output_json"})

SYSTEM_MESSAGE_HANDLING_ALLOWLIST_REVISION = "system-message-handling-allowlist-v1"
SYSTEM_MESSAGE_HANDLINGS: frozenset[str] = frozenset({"system_role", "merge_into_first_user"})


class MockAgentProfile(StrictImmutableBoundaryModel):
    """Deterministic Phase 0A-1 mock profile (never invokes a real model)."""

    profile_type: Literal["mock"] = "mock"
    profile_revision: str = Field(min_length=1)
    profile_digest: str = Field(min_length=1)
    implementation_digest: str = Field(min_length=1)

    def is_usable(self) -> bool:
        """The mock profile is always usable; it calls no external model."""
        return True


class LocalLLMProfile(StrictImmutableBoundaryModel):
    """Version-managed local vLLM profile pinned to ``chat_completions``."""

    profile_type: Literal["vllm"] = "vllm"
    profile_revision: str = Field(min_length=1)
    profile_digest: str = Field(min_length=1)
    wire_api: Literal["chat_completions"]
    structured_output_mode: str = Field(min_length=1)
    tool_output_support: bool
    system_message_handling: str = Field(min_length=1)
    max_context_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)
    model_name: str = Field(min_length=1)
    model_hash: str = Field(min_length=1)
    chat_template_digest: str | None
    tokenizer_revision: str = Field(min_length=1)
    runtime_version: str = Field(min_length=1)

    @model_validator(mode="after")
    def _bounded(self) -> LocalLLMProfile:
        if self.max_output_tokens > self.max_context_tokens:
            raise ValueError("max_output_tokens must not exceed max_context_tokens")
        if self.structured_output_mode not in STRUCTURED_OUTPUT_MODES:
            raise ValueError("structured_output_mode is not in the versioned allowlist")
        if self.system_message_handling not in SYSTEM_MESSAGE_HANDLINGS:
            raise ValueError("system_message_handling is not in the versioned allowlist")
        if self.structured_output_mode == "tool_output_json" and not self.tool_output_support:
            raise ValueError("tool-output structured mode requires tool_output_support")
        return self

    def is_usable(self) -> bool:
        """Structural validity only. A real mission additionally requires a passed
        capability result bound to ``profile_digest`` (verified by the capability
        service); the profile alone never self-attests capability."""
        return True


AgentModelProfile = Annotated[
    LocalLLMProfile | MockAgentProfile,
    Field(discriminator="profile_type"),
]

_PROFILE_ADAPTER: TypeAdapter[LocalLLMProfile | MockAgentProfile] = TypeAdapter(AgentModelProfile)


def parse_agent_profile(raw: str | bytes) -> LocalLLMProfile | MockAgentProfile:
    """Validate untrusted JSON text into a strict agent model profile.

    Duplicate keys are rejected before validation; unknown fields and coercion are
    rejected by the strict boundary models. Errors are content-free.
    """
    parse_json_no_duplicate_keys(raw)  # raises on duplicate keys
    from pydantic import ValidationError

    try:
        return _PROFILE_ADAPTER.validate_json(raw)
    except ValidationError as exc:
        from redteam_agent.canonical.json_boundary import _redact_validation_error

        raise PydanticBoundaryValidationError(_redact_validation_error(exc)) from None


def _digest_payload(profile: LocalLLMProfile | MockAgentProfile) -> dict[str, object]:
    payload = profile.model_dump(mode="python")
    payload.pop("profile_digest", None)
    return payload


def _with_digest(
    profile: LocalLLMProfile | MockAgentProfile, digest_service: DigestService
) -> str:
    return digest_service.compute("profile_digest", _digest_payload(profile))


def build_mock_agent_profile(
    *,
    profile_revision: str = "mock-profile-v1",
    implementation_digest: str = "mock-agent-implementation-v1",
    digest_service: DigestService,
) -> MockAgentProfile:
    draft = MockAgentProfile(
        profile_revision=profile_revision,
        profile_digest="pending",
        implementation_digest=implementation_digest,
    )
    return draft.model_copy(update={"profile_digest": _with_digest(draft, digest_service)})


def build_local_llm_profile(
    *,
    profile_revision: str,
    wire_api: Literal["chat_completions"] = "chat_completions",
    structured_output_mode: str = "native_json_schema",
    tool_output_support: bool = True,
    system_message_handling: str = "system_role",
    max_context_tokens: int,
    max_output_tokens: int,
    model_name: str,
    model_hash: str,
    chat_template_digest: str | None,
    tokenizer_revision: str,
    runtime_version: str,
    digest_service: DigestService,
) -> LocalLLMProfile:
    draft = LocalLLMProfile(
        profile_revision=profile_revision,
        profile_digest="pending",
        wire_api=wire_api,
        structured_output_mode=structured_output_mode,
        tool_output_support=tool_output_support,
        system_message_handling=system_message_handling,
        max_context_tokens=max_context_tokens,
        max_output_tokens=max_output_tokens,
        model_name=model_name,
        model_hash=model_hash,
        chat_template_digest=chat_template_digest,
        tokenizer_revision=tokenizer_revision,
        runtime_version=runtime_version,
    )
    return draft.model_copy(update={"profile_digest": _with_digest(draft, digest_service)})


def mock_agent_profile(
    digest_service: DigestService, profile_revision: str = "mock-profile-v1"
) -> MockAgentProfile:
    """Backward-compatible helper used by Phase 0A-1 wiring and tests."""
    return build_mock_agent_profile(profile_revision=profile_revision, digest_service=digest_service)


def build_agent_profile(
    *,
    profile_revision: str,
    profile_kind: Literal["mock", "local_llm"],
    capability_check_passed: bool,
    digest_service: DigestService,
) -> LocalLLMProfile | MockAgentProfile:
    """Backward-compatible constructor.

    ``capability_check_passed`` is *ignored* for a local profile: a real mission's
    fitness is proven only by a stored capability result bound to ``profile_digest``,
    never by a self-attested boolean (this is exactly the P21 bypass that mission
    validation rejects).
    """
    del capability_check_passed
    if profile_kind == "mock":
        return build_mock_agent_profile(profile_revision=profile_revision, digest_service=digest_service)
    return build_local_llm_profile(
        profile_revision=profile_revision,
        max_context_tokens=8192,
        max_output_tokens=1024,
        model_name="unverified-local-model",
        model_hash="unverified-model-hash",
        chat_template_digest=None,
        tokenizer_revision="unverified-tokenizer",
        runtime_version="unverified-runtime",
        digest_service=digest_service,
    )


def verify_profile_digest(
    profile: LocalLLMProfile | MockAgentProfile, digest_service: DigestService
) -> None:
    """Re-verify a profile's own integrity digest (fail closed)."""
    digest_service.verify("profile_digest", _digest_payload(profile), profile.profile_digest)


__all__ = [
    "STRUCTURED_OUTPUT_MODES",
    "STRUCTURED_OUTPUT_MODE_ALLOWLIST_REVISION",
    "SYSTEM_MESSAGE_HANDLINGS",
    "SYSTEM_MESSAGE_HANDLING_ALLOWLIST_REVISION",
    "WIRE_API",
    "AgentModelProfile",
    "LocalLLMProfile",
    "MockAgentProfile",
    "build_agent_profile",
    "build_local_llm_profile",
    "build_mock_agent_profile",
    "mock_agent_profile",
    "parse_agent_profile",
    "verify_profile_digest",
]
