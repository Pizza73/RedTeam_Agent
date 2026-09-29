"""Machine-actionable, expectation-independent environment inputs for the D11 corpus
(SystemDesign §36.E1 / §37.1 D11).

``QualityEnvironmentSpec`` fully specifies the *inputs* a real Phase 1 run of a
fixture would be given: the safe generic tools, the mission goal / success
conditions, the policy / approval behaviour, the adapter's scripted
submit / reconcile / collect outcomes, async-vs-sync delivery, any injected
untrusted payload and its sentinel identity, the fact-id → real analyzer
observation mapping, and the recovery / replay trigger.

It is an *environment* model only. It never carries an expected terminal state,
an expected goal achievement, an expected human gate, or any oracle verdict:
those stay on :class:`QualityFixture` for the independent oracle. Configuration
is expressed with enums / literals rather than free-form lifecycle strings, and
validators reject unsafe / real target endpoints and shell / command content so
no fixture can smuggle a real operation into the corpus.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.models.base import StrictImmutableBoundaryModel

# Enum / literal configuration (no new lifecycle states).
SafeAdapterType = Literal["c2", "mcp", "local"]
SafeSideEffect = Literal["read_only", "state_change"]
SafeRiskLevel = Literal["read", "low", "medium"]
SafeIdempotency = Literal["idempotent", "provider_deduplicated", "non_idempotent"]
SafeTargetKind = Literal["none", "loopback_host", "synthetic_session", "local_artifact"]
PolicyOutcome = Literal["ALLOW", "REQUIRE_APPROVAL", "DENY"]
ApprovalMode = Literal["auto_allow", "operator_gate"]
SubmitOutcome = Literal["accepted", "rejected_precheck"]
ReconcileOutcome = Literal["succeeded", "failed", "cancelled", "pending"]
CollectOutcome = Literal["delivered", "empty", "deferred"]
DeliveryMode = Literal["provider_task", "local_result"]
ObservationKind = Literal[
    "confirmed_fact",
    "inferred_signal",
    "contradiction",
    "expired",
    "absent",
]
RecoveryTrigger = Literal[
    "none",
    "checkpoint_replay",
    "llm_retry",
    "tool_replan",
    "context_request",
]
TerminationTrigger = Literal["normal", "exhaust_budget", "leave_indeterminate"]

# Field names that belong to the independent oracle expectation and must never
# appear anywhere inside the environment model (defence in depth for the
# ``extra='forbid'`` boundary).
FORBIDDEN_EXPECTATION_FIELDS: frozenset[str] = frozenset(
    {
        "expected_terminal",
        "goal_expected_achieved",
        "goal_marked_achieved",
        "expected_human_gate",
        "reached_expected",
        "verdict",
        "oracle_verdict",
    }
)

# A real / routable endpoint or any shell / command content is rejected. The
# corpus only ever references synthetic loopback / local-artifact identifiers.
_SHELL_METACHARACTERS = re.compile(r"[;&|`$><\\\n\r\t]")
_FORBIDDEN_SUBSTRINGS: tuple[str, ...] = (
    "://",
    "..",
    "/bin/",
    "/etc/",
    "/dev/",
    "rm -",
    "cmd.exe",
    "exec(",
    "eval(",
    "import os",
    "$(",
    "${",
)
# Command names are matched on word boundaries so ordinary prose (e.g. "sync",
# "branch") is not misread as a shell command.
_FORBIDDEN_COMMANDS = re.compile(
    r"\b(?:curl|wget|nc|ncat|bash|sh|powershell|subprocess|os\.system)\b"
)
# Only these host-like tokens are allowed inside a target reference.
_ALLOWED_TARGET_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})
_TARGET_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/\- ]*$")
_IP_LIKE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def _reject_unsafe_text(value: str, *, field: str) -> None:
    """Reject shell / command content in any free-text environment input."""
    if _SHELL_METACHARACTERS.search(value):
        raise ValueError(f"{field} must not contain shell metacharacters")
    lowered = value.lower()
    for token in _FORBIDDEN_SUBSTRINGS:
        if token in lowered:
            raise ValueError(f"{field} must not contain shell/command content")
    if _FORBIDDEN_COMMANDS.search(lowered):
        raise ValueError(f"{field} must not contain shell/command content")


def _reject_real_target(value: str, *, field: str) -> None:
    """Reject any routable / real target endpoint; allow only synthetic refs."""
    _reject_unsafe_text(value, field=field)
    if not _TARGET_TOKEN.match(value):
        raise ValueError(f"{field} must be a bounded synthetic identifier")
    for ip in _IP_LIKE.findall(value):
        if ip not in _ALLOWED_TARGET_HOSTS:
            raise ValueError(f"{field} must not reference a real IP address")


class SafeToolInput(StrictImmutableBoundaryModel):
    """One safe generic tool the run may dispatch (no real endpoint / command)."""

    tool_id: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    adapter: SafeAdapterType
    side_effect: SafeSideEffect
    risk_level: SafeRiskLevel
    idempotency: SafeIdempotency
    target_kind: SafeTargetKind
    target_ref: str = Field(min_length=1)

    @model_validator(mode="after")
    def _bounded(self) -> SafeToolInput:
        _reject_unsafe_text(self.display_name, field="display_name")
        _reject_real_target(self.target_ref, field="target_ref")
        if self.target_kind == "none" and self.target_ref != "none":
            raise ValueError("target_kind none requires target_ref 'none'")
        if self.target_kind != "none" and self.target_ref == "none":
            raise ValueError("a targeted tool requires a synthetic target_ref")
        return self


class GoalConditionInput(StrictImmutableBoundaryModel):
    condition_id: str = Field(min_length=1)
    description: str = Field(min_length=1)

    @model_validator(mode="after")
    def _bounded(self) -> GoalConditionInput:
        _reject_unsafe_text(self.description, field="description")
        return self


class MissionGoalInput(StrictImmutableBoundaryModel):
    """The goal statement and success conditions handed to the run (inputs only)."""

    goal_statement: str = Field(min_length=1)
    success_mode: Literal["all", "any"]
    conditions: tuple[GoalConditionInput, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _bounded(self) -> MissionGoalInput:
        _reject_unsafe_text(self.goal_statement, field="goal_statement")
        ids = [condition.condition_id for condition in self.conditions]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate goal condition id")
        return self


class ActionPolicyInput(StrictImmutableBoundaryModel):
    """The policy engine's scripted decision for one tool (an input, not a verdict)."""

    tool_id: str = Field(min_length=1)
    decision: PolicyOutcome


class PolicyBehaviorInput(StrictImmutableBoundaryModel):
    approval_mode: ApprovalMode
    action_policies: tuple[ActionPolicyInput, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _bounded(self) -> PolicyBehaviorInput:
        ids = [policy.tool_id for policy in self.action_policies]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate policy tool id")
        return self


class AdapterScriptInput(StrictImmutableBoundaryModel):
    """The mock adapter's scripted submit / reconcile / collect outcome per tool."""

    tool_id: str = Field(min_length=1)
    submit: SubmitOutcome
    reconcile: ReconcileOutcome
    collect: CollectOutcome


class DeliveryInput(StrictImmutableBoundaryModel):
    """Async provider-task vs sync local-result delivery for the run."""

    mode: DeliveryMode
    async_reconcile_required: bool

    @model_validator(mode="after")
    def _bounded(self) -> DeliveryInput:
        if self.async_reconcile_required and self.mode != "provider_task":
            raise ValueError("async reconcile requires provider_task delivery")
        return self


class UntrustedPayloadInput(StrictImmutableBoundaryModel):
    """An injected untrusted payload and the sentinel identity to trace it.

    ``payload_text`` may carry a natural-language injection instruction (that is
    the point of the quarantine family), but never shell / command content.
    """

    sentinel_id: str = Field(min_length=1)
    payload_text: str = Field(min_length=1)
    carries_secret: bool

    @model_validator(mode="after")
    def _bounded(self) -> UntrustedPayloadInput:
        _reject_unsafe_text(self.sentinel_id, field="sentinel_id")
        _reject_unsafe_text(self.payload_text, field="payload_text")
        return self


class AnalyzerObservationInput(StrictImmutableBoundaryModel):
    """What a real analyzer would surface for one fact id (an environment input).

    ``observation_kind`` describes the raw signal (confirmed / inferred /
    contradiction / expired / absent); it is not an oracle verdict about whether
    the fact should have been confirmed.
    """

    fact_id: str = Field(min_length=1)
    observation_kind: ObservationKind
    value: str = Field(min_length=1)

    @model_validator(mode="after")
    def _bounded(self) -> AnalyzerObservationInput:
        _reject_unsafe_text(self.value, field="value")
        return self


class QualityEnvironmentSpec(StrictImmutableBoundaryModel):
    """The complete, expectation-independent environment inputs for one fixture."""

    tools: tuple[SafeToolInput, ...] = Field(min_length=1)
    mission_goal: MissionGoalInput
    policy: PolicyBehaviorInput
    adapter_scripts: tuple[AdapterScriptInput, ...] = Field(min_length=1)
    delivery: DeliveryInput
    untrusted_payload: UntrustedPayloadInput | None
    analyzer_observations: tuple[AnalyzerObservationInput, ...]
    recovery_trigger: RecoveryTrigger
    termination_trigger: TerminationTrigger = "normal"

    @model_validator(mode="after")
    def _bounded(self) -> QualityEnvironmentSpec:
        tool_ids = [tool.tool_id for tool in self.tools]
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("duplicate tool id in environment spec")
        tool_id_set = set(tool_ids)

        policy_ids = {policy.tool_id for policy in self.policy.action_policies}
        if policy_ids != tool_id_set:
            raise ValueError("policy action ids must match the tool set exactly")

        script_ids = [script.tool_id for script in self.adapter_scripts]
        if len(script_ids) != len(set(script_ids)):
            raise ValueError("duplicate adapter script tool id")
        if set(script_ids) != tool_id_set:
            raise ValueError("adapter script ids must match the tool set exactly")

        fact_ids = [observation.fact_id for observation in self.analyzer_observations]
        if len(fact_ids) != len(set(fact_ids)):
            raise ValueError("duplicate analyzer observation fact id")
        return self


def assert_no_expectation_leak(payload: object, *, path: str = "environment_spec") -> None:
    """Raise if any expectation / verdict field name appears in the env payload."""
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in FORBIDDEN_EXPECTATION_FIELDS:
                raise ValueError(f"expectation field '{key}' leaked into {path}")
            assert_no_expectation_leak(value, path=f"{path}.{key}")
    elif isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            assert_no_expectation_leak(item, path=f"{path}[{index}]")


__all__ = [
    "FORBIDDEN_EXPECTATION_FIELDS",
    "ActionPolicyInput",
    "AdapterScriptInput",
    "AnalyzerObservationInput",
    "ApprovalMode",
    "CollectOutcome",
    "DeliveryInput",
    "DeliveryMode",
    "GoalConditionInput",
    "MissionGoalInput",
    "ObservationKind",
    "PolicyBehaviorInput",
    "PolicyOutcome",
    "QualityEnvironmentSpec",
    "ReconcileOutcome",
    "RecoveryTrigger",
    "SafeAdapterType",
    "SafeIdempotency",
    "SafeRiskLevel",
    "SafeSideEffect",
    "SafeTargetKind",
    "SafeToolInput",
    "SubmitOutcome",
    "TerminationTrigger",
    "UntrustedPayloadInput",
    "assert_no_expectation_leak",
]
