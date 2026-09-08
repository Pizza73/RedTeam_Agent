"""Composition-owned isolated Phase 1 runner for the formal D11 qualification.

Every quality attempt receives a fresh in-memory authorization/workflow kernel and a
side-effect-free adapter.  Only the model client is external.  Oracle expectations are
not accepted by this component; it consumes :class:`QualityWorkflowInput` only and
returns evidence read from workflow results and repositories.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Mapping
from datetime import timedelta

from pydantic import BaseModel

from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.agent.models import ActionCandidateSeed, PlannerContextEnvelope, PlannerFeedback
from redteam_agent.agent.workflow import PlanningOperationIds, WorkflowStepResult
from redteam_agent.auth.models import MissionRoleAssignment
from redteam_agent.composition.phase1 import Phase1Kernel
from redteam_agent.composition.testing import (
    ADMIN_ACTOR_TOKEN,
    ADMIN_PRINCIPAL_ID,
    OPERATOR_ACTOR_TOKEN,
    OPERATOR_PRINCIPAL_ID,
)
from redteam_agent.context.builder import ContextBodyRecord
from redteam_agent.context.models import ContextResourceIndexRecord
from redteam_agent.context.selector import ContextSelector
from redteam_agent.contracts.catalog import ActionContractDefinition, parameter_schema_digest
from redteam_agent.errors import LLMEvaluationError
from redteam_agent.execution.models import ExecutionResult
from redteam_agent.execution.thread import compute_thread_id
from redteam_agent.knowledge.models import KnowledgeObservation
from redteam_agent.llm.adapters import LocalLLMAnalyzer, LocalLLMPlanner
from redteam_agent.llm.binding import MissionBindingChecker
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.profile import LocalLLMProfile
from redteam_agent.llm.tokenizer import TokenCounter
from redteam_agent.mission.manager import MISSION_ADMIN_ROLE, MISSION_OPERATOR_ROLE
from redteam_agent.mission.models import (
    ApprovalPolicy,
    ExactSessionSelector,
    MissionRevision,
    SessionExistsCondition,
    compute_mission_revision_digest,
)
from redteam_agent.models.common import ToolRef
from redteam_agent.policy.data_access import DataAccessPolicy, DataAccessRule
from redteam_agent.policy.scope_models import IpTargetReference, NetworkScopeRule
from redteam_agent.quality.models import QualityAttemptFailure, RunDiagnostics
from redteam_agent.quality.workflow_driver import QualityWorkflowInput, WorkflowRunTrace
from redteam_agent.resources.resource_metadata import ResourceMetadata
from redteam_agent.session.models import SessionSecurityContext, SessionSecurityContextSnapshot
from redteam_agent.tools.models import ToolDefinition
from redteam_agent.tools.registry import build_tool_registry

ScenarioKernelFactory = Callable[[QualityWorkflowInput], Phase1Kernel]


def _seed_number(seed: str, offset: int) -> int:
    value = hashlib.sha256(f"{seed}:{offset}".encode()).digest()
    return int.from_bytes(value[:4], "big") & 0x7FFF_FFFF


def _tool_definition(
    tool_id: str,
    *,
    adapter_id: str,
    adapter_type: str,
    side_effect: str,
    idempotency: str,
    approval_rule: str,
    deny_probe: bool,
) -> tuple[ToolDefinition, ActionContractDefinition]:
    schema = (
        {
            "type": "object",
            "properties": {
                "destinations": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                }
            },
            "required": ["destinations"],
            "additionalProperties": False,
        }
        if deny_probe
        else {"type": "object", "properties": {}, "additionalProperties": False}
    )
    contract = ActionContractDefinition(
        contract_id=f"quality-contract-{tool_id}",
        revision="1",
        tool_id=tool_id,
        registry_revision=1,
        parameter_schema_digest=parameter_schema_digest(schema),
        target_extractor_id="network_target_v1" if deny_probe else None,
        evidence_rule_ids=("ev-1",),
        output_publication_rule_id="pub-1",
        minimum_risk_level="read" if side_effect == "read_only" else "low",
        side_effect=side_effect,
    )
    tool = ToolDefinition(
        tool_ref=ToolRef(tool_id=tool_id, registry_revision=1),
        display_name=f"Quality action {tool_id}",
        version="1",
        description="Perform one bounded operation in the isolated quality simulator.",
        adapter=adapter_type,  # type: ignore[arg-type]
        adapter_id=adapter_id,
        provider_tool_name=tool_id,
        provider_definition_revision="1",
        provider_schema_digest=parameter_schema_digest(schema),
        minimum_risk_level="read" if side_effect == "read_only" else "low",
        approval_rule=approval_rule,  # type: ignore[arg-type]
        side_effect=side_effect,  # type: ignore[arg-type]
        idempotency=idempotency,  # type: ignore[arg-type]
        parameter_schema=schema,
        output_publication_rule_id="pub-1",
        evidence_rule_ids=("ev-1",),
        action_contract_ref=contract.reference(),
        target_mode="required" if deny_probe else "none",
        target_extractor_id="network_target_v1" if deny_probe else None,
        default_timeout_seconds=30,
        max_timeout_seconds=60,
        max_output_bytes=64 * 1024,
        secret_argument_paths=(),
        requires_session=False,
        supported_os=frozenset({"linux"}),
        supported_architectures=frozenset({"x86_64"}),
        required_adapter_capabilities=frozenset(),
        required_session_capabilities=frozenset(),
        required_data_access_types=frozenset(),
        required_target_binding_modes=(frozenset({"exact_ip_enforced"}) if deny_probe else frozenset({"none"})),
        sandbox_requirement=None,
    )
    return tool, contract


class _UsageTally:
    """Per-run LLM token-usage accumulator (local to one :meth:`__call__` invocation).

    Holding this as a plain local object -- never shared class/module state -- is what
    keeps concurrent runs isolated under :meth:`WorkflowBackedQualityDriver.drive_many`:
    each thread owns exactly one tally, built and consumed inside its own call frame.
    """

    __slots__ = ("completion_tokens", "llm_calls", "prompt_tokens", "retries", "usage_missing", "validation_errors")

    def __init__(self) -> None:
        self.llm_calls = 0
        self.retries = 0
        self.validation_errors = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.usage_missing = 0

    def record(self, usage_records: tuple[tuple[int | None, int | None], ...]) -> None:
        if not usage_records:
            return
        self.llm_calls += len(usage_records)
        # Every attempt beyond the first for one logical operation is an
        # output-validation retry (the gateway never retries a transport error).
        self.retries += len(usage_records) - 1
        self.validation_errors += len(usage_records) - 1
        for prompt_tokens, completion_tokens in usage_records:
            if prompt_tokens is None or completion_tokens is None:
                self.usage_missing += 1
                continue
            self.prompt_tokens += prompt_tokens
            self.completion_tokens += completion_tokens


class _RecoveryTally:
    """Mutable checkpoint-recovery counters, shared across a scenario call and its
    exception handler so a partial count survives a mid-run failure (see :class:`_UsageTally`).
    """

    __slots__ = ("attempts", "successes")

    def __init__(self) -> None:
        self.attempts = 0
        self.successes = 0


class IsolatedPhase1ScenarioRunner:
    """Execute one expectation-free fixture through a fresh product workflow kernel."""

    def __init__(
        self,
        *,
        kernel_factory: ScenarioKernelFactory,
        planner_factory: Callable[[Phase1Kernel], LocalLLMPlanner],
        analyzer_factory: Callable[[Phase1Kernel], LocalLLMAnalyzer],
        profile: LocalLLMProfile,
        client: VLLMChatClient,
        token_counter: TokenCounter,
    ) -> None:
        self._kernel_factory = kernel_factory
        self._planner_factory = planner_factory
        self._analyzer_factory = analyzer_factory
        self._profile = profile
        # The one trusted client/tokenizer this runner's evidence is bound to. Every
        # planner/analyzer the factories produce is verified against these exact
        # objects on every call -- a factory closure cannot silently swap in a
        # different (fake) transport or tokenizer after construction-time checks.
        self._client = client
        self._token_counter = token_counter

    def is_bound_to(self, *, client: VLLMChatClient, token_counter: TokenCounter, profile_digest: str) -> bool:
        """Whether this runner's trace-producing evidence is bound to the given identity.

        Checked by the driver at ``evidence_kind`` time against the exact objects the
        real qualification is constructed with, and against the evaluation binding's
        profile digest -- never a type/class check alone.
        """
        return (
            self._client is client
            and self._token_counter is token_counter
            and self._profile.profile_digest == profile_digest
        )

    def _verify_factory_binding(self, planner: LocalLLMPlanner, analyzer: LocalLLMAnalyzer) -> None:
        """Reject a planner/analyzer that a factory built against a different identity.

        ``planner_factory``/``analyzer_factory`` are caller-controlled closures; the
        constructor-time ``client``/``token_counter`` recorded above only prove this
        runner *claims* an identity, not that every produced adapter actually uses it.
        This runtime check closes that gap: it fails closed rather than letting a
        mismatched or injected inner factory pass as real evidence.
        """
        mismatched = (
            planner.client is not self._client
            or planner.token_counter is not self._token_counter
            or planner.profile is not self._profile
            or analyzer.client is not self._client
            or analyzer.token_counter is not self._token_counter
            or analyzer.profile is not self._profile
        )
        if mismatched:
            raise LLMEvaluationError(
                "isolated scenario runner factories produced a planner/analyzer not bound "
                "to this runner's trusted client/tokenizer/profile"
            )

    def __call__(
        self,
        workflow: object,
        planner: LocalLLMPlanner,
        analyzer: LocalLLMAnalyzer,
        run_input: QualityWorkflowInput,
        attempt_index: int,
        seed: str,
    ) -> WorkflowRunTrace:
        # The shared objects belong to the binding driver.  Each run intentionally uses
        # fresh equivalents over an isolated database.
        del workflow, planner, analyzer
        phase1 = self._kernel_factory(run_input)
        planner = self._planner_factory(phase1)
        analyzer = self._analyzer_factory(phase1)
        self._verify_factory_binding(planner, analyzer)
        # Initialized before the fallible scenario body so a failure at any point below
        # can still report the diagnostics actually observed up to that point -- a run
        # that consumed real LLM network attempts is never durably recorded as if it
        # had consumed none.
        steps: list[WorkflowStepResult] = []
        planner_latencies: list[int] = []
        analyzer_latencies: list[int] = []
        usage = _UsageTally()
        recovery = _RecoveryTally()
        try:
            return self._run_scenario(
                phase1,
                planner,
                analyzer,
                run_input,
                attempt_index,
                seed,
                steps=steps,
                planner_latencies=planner_latencies,
                analyzer_latencies=analyzer_latencies,
                usage=usage,
                recovery=recovery,
            )
        except LLMEvaluationError:
            # A driver-contract violation is a hard error, never a scored attempt.
            raise
        except Exception as exc:
            # An ordinary model / output-validation failure. Its exact diagnostics --
            # every real LLM network attempt already made, its usage, and its retries
            # -- are preserved rather than replaced by a fabricated zero.
            raise QualityAttemptFailure(
                original_exception_type=type(exc).__name__,
                diagnostics=self._diagnostics_snapshot(
                    phase1=phase1,
                    steps=steps,
                    usage=usage,
                    recovery=recovery,
                    planner_latencies=planner_latencies,
                    analyzer_latencies=analyzer_latencies,
                ),
            ) from exc

    @staticmethod
    def _diagnostics_snapshot(
        *,
        phase1: Phase1Kernel,
        steps: list[WorkflowStepResult],
        usage: _UsageTally,
        recovery: _RecoveryTally,
        planner_latencies: list[int],
        analyzer_latencies: list[int],
    ) -> RunDiagnostics:
        """The exact §36.E1 diagnostics observed so far.

        Shared by the completed-trace path and the failure path so a run that fails
        after one or more real LLM network attempts reports precisely what those
        attempts consumed -- never a fabricated zero.
        """
        adapter = phase1.phase0c.phase0b.mock_adapter
        return RunDiagnostics(
            tool_dispatches=adapter.submit_calls,
            action_attempts=sum(step.planner_output is not None for step in steps),
            llm_calls=usage.llm_calls,
            retries=usage.retries,
            validation_errors=usage.validation_errors,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            usage_missing_count=usage.usage_missing,
            provider_reconciliations=adapter.reconcile_calls,
            checkpoint_recovery_attempts=recovery.attempts,
            checkpoint_recovery_successes=recovery.successes,
            planner_latencies_ms=tuple(planner_latencies),
            analyzer_latencies_ms=tuple(analyzer_latencies),
        )

    def _run_scenario(
        self,
        phase1: Phase1Kernel,
        planner: LocalLLMPlanner,
        analyzer: LocalLLMAnalyzer,
        run_input: QualityWorkflowInput,
        attempt_index: int,
        seed: str,
        *,
        steps: list[WorkflowStepResult],
        planner_latencies: list[int],
        analyzer_latencies: list[int],
        usage: _UsageTally,
        recovery: _RecoveryTally,
    ) -> WorkflowRunTrace:
        """The fallible scenario body.  ``steps``/``usage``/latencies are mutated in
        place so the caller can report exactly what happened even if this raises.
        """
        tools = self._seed_mission(phase1, run_input, attempt_index)
        mission_id = self._mission_id(run_input, attempt_index)
        run_id = f"quality-run-{attempt_index}"
        thread_id = compute_thread_id(mission_id=mission_id, mission_revision=1, run_id=run_id)
        extracted: list[str] = []
        leaked = False
        planning_iterations = 0
        analysis_index = 0
        replan_parent: str | None = None
        recovery_reconciled = False
        last_planner_context_id: str | None = None

        env = run_input.environment_spec
        observations = env.analyzer_observations
        policies = {item.tool_id: item.decision for item in env.policy.action_policies}
        scripts = {item.tool_id: item for item in env.adapter_scripts}
        action_runs: list[tuple[ToolDefinition, dict[str, object], tuple[IpTargetReference, ...], bool]] = []
        for tool in tools:
            if policies[tool.tool_ref.tool_id] == "DENY":
                action_runs.extend(
                    (
                        (
                            tool,
                            {"destinations": ["192.0.2.1"]},
                            (IpTargetReference(type="ip", address="127.0.0.1"),),
                            False,
                        ),
                        (
                            tool,
                            {"destinations": ["127.0.0.1"]},
                            (IpTargetReference(type="ip", address="127.0.0.1"),),
                            False,
                        ),
                    )
                )
            elif scripts[tool.tool_ref.tool_id].reconcile == "failed":
                action_runs.extend(((tool, {}, (), True), (tool, {}, (), False)))
            else:
                action_runs.append((tool, {}, (), False))
        if env.termination_trigger == "exhaust_budget":
            base = action_runs
            repeats = (run_input.max_iterations + len(base) - 1) // len(base)
            action_runs = (base * repeats)[: run_input.max_iterations]

        next_index = 0
        if env.recovery_trigger == "context_request":
            planning_iterations += 1
            envelope = self._planner_envelope(
                phase1,
                run_input,
                mission_id=mission_id,
                tool=tools[0],
                index=next_index,
                suggested_arguments={},
                targets=(),
                parent_context_id=None,
                force_context_request=True,
            )
            invocation = planner.build_invocation(
                envelope,
                deadline=phase1.phase0c.monotonic_clock.now() + timedelta(seconds=120),
                seed=_seed_number(seed, next_index),
                binding_checker=self._binding_checker(phase1, mission_id),
            )
            ids = PlanningOperationIds(
                operation_id="planner-context-request",
                plan_id="unused-context-plan",
                run_id=run_id,
                thread_id=thread_id,
                decision_id="unused-context-decision",
                execution_id="unused-context-execution",
                task_id="unused-context-task",
            )
            started = time.monotonic()
            step = phase1.workflow.run_planning_iteration(
                envelope=envelope, ids=ids, invoke_planner=invocation
            )
            planner_latencies.append(round((time.monotonic() - started) * 1000))
            usage.record(invocation.usage_records)
            steps.append(step)
            last_planner_context_id = envelope.planner_context_id
            leaked = leaked or self._contains_secret(step.planner_output, run_input)
            if step.planner_output is None or getattr(step.planner_output, "output_type", None) != "context_request":
                raise RuntimeError("insufficient-context scenario did not request typed context")
            replan_parent = envelope.planner_context_id
            next_index = 1

        for action_offset, (tool, arguments, targets, fail_delivery) in enumerate(action_runs):
            index = next_index + action_offset
            planning_iterations += 1
            envelope = self._planner_envelope(
                phase1,
                run_input,
                mission_id=mission_id,
                tool=tool,
                index=index,
                suggested_arguments=arguments,
                targets=targets,
                parent_context_id=replan_parent,
            )
            replan_parent = None
            binding = self._binding_checker(phase1, mission_id)
            invocation = planner.build_invocation(
                envelope,
                deadline=phase1.phase0c.monotonic_clock.now() + timedelta(seconds=120),
                seed=_seed_number(seed, index),
                binding_checker=binding,
            )
            ids = PlanningOperationIds(
                operation_id=f"planner-{index}",
                plan_id=f"plan-{index}",
                run_id=run_id,
                thread_id=thread_id,
                decision_id=f"decision-{index}",
                execution_id=f"execution-{index}",
                task_id=f"task-{index}",
            )
            started = time.monotonic()
            step = phase1.workflow.run_planning_iteration(envelope=envelope, ids=ids, invoke_planner=invocation)
            planner_latencies.append(round((time.monotonic() - started) * 1000))
            usage.record(invocation.usage_records)
            steps.append(step)
            last_planner_context_id = envelope.planner_context_id
            leaked = leaked or self._contains_secret(step.planner_output, run_input)
            transition = step.action_transition
            if transition is not None and transition.decision.decision == "DENY":
                replan_parent = envelope.planner_context_id
            if transition is not None and transition.decision.decision == "REQUIRE_APPROVAL":
                current = phase1.phase0c.phase0b.phase0a.state_repository.get(mission_id)
                assert current is not None
                phase1.phase0c.phase0b.phase0a.mission_manager.pause_mission(
                    mission_id,
                    expected_version=current.mission_state_version,
                    actor_token=OPERATOR_ACTOR_TOKEN,
                )
                break
            if transition is None or transition.dispatch is None:
                continue
            adapter = phase1.phase0c.phase0b.mock_adapter
            if env.recovery_trigger == "checkpoint_replay" and action_offset == 0:
                recovery.attempts += 1
                before_submit_calls = adapter.submit_calls
                replay = phase1.workflow.run_planning_iteration(
                    envelope=envelope,
                    ids=ids,
                    invoke_planner=lambda _envelope: (_ for _ in ()).throw(
                        AssertionError("checkpoint replay must not call the planner")
                    ),
                )
                steps.append(replay)
                if adapter.reconcile_calls > 0 and adapter.submit_calls == before_submit_calls:
                    recovery.successes += 1
                    recovery_reconciled = True
            elif env.delivery.async_reconcile_required:
                phase1.phase0c.phase0b.reconciliation.reconcile(
                    execution_id=ids.execution_id
                )
                recovery_reconciled = adapter.reconcile_calls > 0
            adapter._collect_status = "failed" if fail_delivery else "succeeded"
            adapter._collect_exit_code = 1 if fail_delivery else 0
            result = self._finish_execution(phase1, ids.execution_id)
            if result is None or result.status != "SUCCEEDED" or analysis_index >= len(observations):
                continue
            candidate = observations[analysis_index]
            observation, latency, analyzer_usage = self._analyze(
                phase1,
                analyzer,
                run_input,
                mission_id=mission_id,
                run_id=run_id,
                thread_id=thread_id,
                execution_id=ids.execution_id,
                index=analysis_index,
                fact_id=candidate.fact_id,
                seed=_seed_number(seed, 100 + index),
            )
            analyzer_latencies.append(latency)
            usage.record(analyzer_usage)
            leaked = leaked or self._contains_secret(observation, run_input)
            if observation.object_ref == candidate.fact_id:
                extracted.append(candidate.fact_id)
            analysis_index += 1

        has_conflict = any(item.observation_kind in ("contradiction", "expired") for item in observations)
        if env.termination_trigger == "exhaust_budget":
            self._record_limit_stop(
                phase1, mission_id, run_id, thread_id, steps, last_planner_context_id
            )
        elif observations and not has_conflict:
            self._seed_goal_session(phase1, mission_id)
            self._finish_mission(
                phase1, mission_id, run_id, thread_id, steps, last_planner_context_id
            )
        elif has_conflict:
            self._abort_unachieved_mission(phase1, mission_id)

        state = phase1.phase0c.phase0b.phase0a.state_repository.get(mission_id)
        if state is None:
            raise RuntimeError("isolated scenario lost its mission state")
        goal = phase1.goal_service.evaluate(mission_id=mission_id).status.status
        adapter = phase1.phase0c.phase0b.mock_adapter
        return WorkflowRunTrace(
            steps=tuple(steps),
            final_mission_state=state.state,
            goal_status=goal,
            iterations=planning_iterations,
            recovery_reconciled=recovery_reconciled,
            duplicate_dispatch_count=max(0, adapter.submit_calls - len(adapter.submissions)),
            extracted_facts=tuple(dict.fromkeys(extracted)),
            confirmed_facts=(),
            secret_leaked=leaked,
            diagnostics=self._diagnostics_snapshot(
                phase1=phase1,
                steps=steps,
                usage=usage,
                recovery=recovery,
                planner_latencies=planner_latencies,
                analyzer_latencies=analyzer_latencies,
            ),
        )

    @staticmethod
    def _mission_id(run_input: QualityWorkflowInput, attempt_index: int) -> str:
        return f"quality-{run_input.fixture_id}-{attempt_index}"

    def _seed_mission(
        self, phase1: Phase1Kernel, run_input: QualityWorkflowInput, attempt_index: int
    ) -> tuple[ToolDefinition, ...]:
        a = phase1.phase0c.phase0b.phase0a
        ds = a.digest_service
        env = run_input.environment_spec
        adapter_id = phase1.phase0c.phase0b.mock_adapter.identity().adapter_id
        policy_by_tool = {item.tool_id: item.decision for item in env.policy.action_policies}
        base = [
            _tool_definition(
                item.tool_id,
                adapter_id=adapter_id,
                adapter_type=item.adapter,
                side_effect=item.side_effect,
                idempotency=item.idempotency,
                approval_rule=("always" if policy_by_tool[item.tool_id] == "REQUIRE_APPROVAL" else "policy"),
                deny_probe=policy_by_tool[item.tool_id] == "DENY",
            )
            for item in env.tools
        ]
        tools = tuple(item[0] for item in base)
        for _tool, contract in base:
            a.contract_catalog.register(contract)
        a.rule_catalog.register_publication("pub-1")
        a.rule_catalog.register_evidence("ev-1")
        a.registry_repository.save(
            build_tool_registry(
                registry_revision=1,
                tools=tools,
                digest_service=ds,
                contract_catalog=a.contract_catalog,
                rule_catalog=a.rule_catalog,
            )
        )
        identity = phase1.phase0c.phase0b.mock_adapter.identity()
        a.adapter_repository.save(
            AdapterCapabilities(
                adapter_id=adapter_id,
                adapter_type=env.tools[0].adapter,
                execution_location="local_process",
                capability_revision="quality-v1",
                capabilities=frozenset({"scan"}),
                supported_os=frozenset({"linux"}),
                supported_architectures=frozenset({"x86_64"}),
                reconciliation=True,
                cancellation=True,
                provider_deduplication=True,
                result_streaming=True,
                result_resume=True,
                durable_result_collection=True,
                result_delivery_mode=identity.result_delivery_mode,
                target_binding_modes=frozenset({"none", "exact_ip_enforced"}),
                redirect_disable_enforcement=True,
                policy_intercepted_redirect=False,
                max_output_bytes=64 * 1024,
                provider_tool_catalog_digest=None,
                observed_at=a.clock.now(),
            )
        )
        mission_id = self._mission_id(run_input, attempt_index)
        for principal, role in (
            (ADMIN_PRINCIPAL_ID, MISSION_ADMIN_ROLE),
            (OPERATOR_PRINCIPAL_ID, MISSION_OPERATOR_ROLE),
        ):
            a.role_assignment_repository.save(
                MissionRoleAssignment(mission_id=mission_id, principal_id=principal, role=role, active=True)
            )
        now = a.clock.now()
        profile = self._profile
        # The Phase 1 semantic catalog has a closed, pre-registered synthetic
        # session vocabulary.  Each run has a fresh database, so the same safe
        # ``sess-1`` identity cannot cross-contaminate attempts.
        session_id = "sess-1"
        fields = {
            "mission_id": mission_id,
            "mission_revision": 1,
            "llm_profile_revision": profile.profile_revision,
            "llm_profile_digest": profile.profile_digest,
            "description": env.mission_goal.goal_statement,
            "authorization_reference": "isolated-quality-simulator-v1",
            "authorized_by": "phase2-composition",
            "valid_from": now - timedelta(minutes=1),
            "valid_until": now + timedelta(hours=1),
            "recovery_until": now + timedelta(hours=2),
            "evidence_retention_until": now + timedelta(hours=3),
            "allowed_execution_scope": (NetworkScopeRule(type="network", cidrs=("127.0.0.0/8",)),),
            "prohibited_execution_scope": (),
            "data_access_policy": DataAccessPolicy(
                allowed=(
                    DataAccessRule(
                        resource_type="internal_knowledge",
                        resource_pattern=f"prefix:{mission_id}",
                        operations=frozenset({"read"}),
                    ),
                ),
                prohibited=(),
            ),
            "objectives": (env.mission_goal.goal_statement,),
            "success_conditions": (
                SessionExistsCondition(
                    condition_id=env.mission_goal.conditions[0].condition_id,
                    session_selector=ExactSessionSelector(session_ref=session_id),
                ),
            ),
            "success_mode": env.mission_goal.success_mode,
            "max_iterations": run_input.max_iterations,
            "max_runtime_minutes": 30,
            "approval_policy": ApprovalPolicy(
                require_for_risk=frozenset(),
                require_for_side_effect=(
                    frozenset({"state_change"}) if env.policy.approval_mode == "operator_gate" else frozenset()
                ),
                approval_ttl_seconds=300,
                count_approval_wait_in_runtime=False,
            ),
        }
        revision = MissionRevision(**fields, mission_revision_digest="pending")  # type: ignore[arg-type]
        digest_fields = revision.model_dump(mode="python")
        digest_fields.pop("mission_revision_digest")
        revision = revision.model_copy(
            update={"mission_revision_digest": compute_mission_revision_digest(digest_fields, ds)}
        )
        a.mission_manager.create_mission(revision, actor_token=ADMIN_ACTOR_TOKEN)
        a.mission_manager.validate_mission(mission_id, expected_version=0, actor_token=OPERATOR_ACTOR_TOKEN)
        a.mission_manager.start_mission(mission_id, expected_version=1, actor_token=OPERATOR_ACTOR_TOKEN)
        phase1.phase0c.phase0b.budget_service.create_budget(
            mission_id=mission_id,
            mission_revision=1,
            max_dispatch_claims=run_input.max_iterations,
        )
        phase1.knowledge_service.initialize_mission(mission_id=mission_id, mission_revision=1, recorded_at=now)
        if env.untrusted_payload is not None:
            self._put_context(
                phase1,
                mission_id,
                "planner-untrusted",
                {
                    "scenario_stimulus": run_input.scenario_stimulus,
                    "untrusted_payload": env.untrusted_payload.payload_text,
                    "sentinel_id": env.untrusted_payload.sentinel_id,
                },
            )
        if env.recovery_trigger == "context_request":
            self._put_context(
                phase1,
                mission_id,
                "requested-context",
                {
                    "scenario_stimulus": run_input.scenario_stimulus,
                    "initial_facts": list(run_input.initial_facts),
                },
            )
        return tools

    def _planner_envelope(
        self,
        phase1: Phase1Kernel,
        run_input: QualityWorkflowInput,
        *,
        mission_id: str,
        tool: ToolDefinition | None,
        index: int,
        suggested_arguments: dict[str, object],
        targets: tuple[IpTargetReference, ...],
        parent_context_id: str | None,
        force_context_request: bool = False,
    ) -> PlannerContextEnvelope:
        a = phase1.phase0c.phase0b.phase0a
        snapshot = a.tool_availability_service.publish(snapshot_id=f"snapshot-{index}", mission_id=mission_id)
        goal = phase1.goal_service.evaluate(mission_id=mission_id)
        head = phase1.knowledge_service.verify_current_head(mission_id)
        seeds = (
            (
                ActionCandidateSeed(
                    tool_ref=tool.tool_ref,
                    canonical_target_binding=targets,
                    satisfied_precondition_refs=(),
                    objective_dependency_ids=("mission-objective-0",),
                    suggested_arguments=suggested_arguments,
                ),
            )
            if tool is not None
            else ()
        )
        projection = phase1.candidate_projector.build(
            snapshot_id=snapshot.snapshot_id,
            seeds=seeds,
            source_version_digests=(goal.evaluation_digest, head.head_digest),
        )
        resource_ids: tuple[str, ...] = ()
        if run_input.environment_spec.untrusted_payload is not None:
            resource_ids = (f"{mission_id}/planner-untrusted",)
        if (
            parent_context_id is not None
            and run_input.environment_spec.recovery_trigger == "context_request"
        ):
            resource_ids = (*resource_ids, f"{mission_id}/requested-context")
        grant = a.context_authorization_service.issue_grant(
            grant_id=f"planner-grant-{index}",
            mission_id=mission_id,
            service_identity="planner_context",
            candidate_resource_ids=resource_ids,
            session_ids=(),
            ttl_seconds=180,
        )
        budget = phase1.phase0c.phase0b.budget_repository.get(mission_id, 1)
        assert budget is not None
        return phase1.planner_context_service.build(
            planner_context_id=f"planner-context-{index}",
            mission_id=mission_id,
            goal_evaluation_id=goal.evaluation_id,
            projection=projection,
            context_grant_id=grant.grant_id,
            available_tool_snapshot_id=snapshot.snapshot_id,
            iteration=budget.consumed_dispatch_claims,
            ranked_candidate_metadata=ContextSelector(a.index_repository).select(mission_id, frozenset()),
            operational_phase="DISCOVERY",
            parent_context_id=parent_context_id,
            feedback=(
                (
                    PlannerFeedback(
                        reason_code="POLICY_DENIED",
                        safe_summary="The proposed action was denied by current policy.",
                        visible_tool_ref=tool.tool_ref if tool is not None else None,
                    ),
                )
                if (
                    parent_context_id is not None
                    and run_input.environment_spec.recovery_trigger != "context_request"
                )
                else ()
            ),
            truncation_reason_codes=(
                ("QUALITY_CONTEXT_REQUIRED",) if force_context_request else ()
            ),
        )

    @staticmethod
    def _binding_checker(phase1: Phase1Kernel, mission_id: str) -> MissionBindingChecker:
        a = phase1.phase0c.phase0b.phase0a
        state = a.state_repository.get(mission_id)
        revision = a.revision_repository.get(mission_id, 1)
        assert state is not None and revision is not None
        return MissionBindingChecker(
            context_resolver=a.context_resolver,
            clock=phase1.phase0c.monotonic_clock,
            mission_id=mission_id,
            expected_profile_digest=revision.llm_profile_digest,
            expected_revision=1,
            expected_epoch=state.authorization_epoch,
        )

    @staticmethod
    def _finish_execution(phase1: Phase1Kernel, execution_id: str) -> ExecutionResult | None:
        phase0b = phase1.phase0c.phase0b
        phase0b.collection_coordinator.collect(execution_id=execution_id)
        phase0b.ingestion_coordinator.ingest(execution_id=execution_id)
        return phase1.phase0c.phase0b.result_repository.get(execution_id)

    def _analyze(
        self,
        phase1: Phase1Kernel,
        analyzer: LocalLLMAnalyzer,
        run_input: QualityWorkflowInput,
        *,
        mission_id: str,
        run_id: str,
        thread_id: str,
        execution_id: str,
        index: int,
        fact_id: str,
        seed: int,
    ) -> tuple[KnowledgeObservation, int, tuple[tuple[int | None, int | None], ...]]:
        a = phase1.phase0c.phase0b.phase0a
        result = phase1.phase0c.phase0b.result_repository.get(execution_id)
        assert result is not None
        condition_id = run_input.environment_spec.mission_goal.conditions[0].condition_id
        body: dict[str, object] = {
            "analysis_task": {
                "observation_id": f"observation-{index}",
                "condition_id": condition_id,
                "source_execution_id": execution_id,
                "observation_type": "finding",
                "subject_ref": "host:isolated-loopback",
                "predicate": "session_candidate",
                "object_ref": fact_id,
                "attributes": {"fact_id": fact_id},
                "source_artifact_ids": list(result.redacted_artifact_ids),
                "llm_confidence": 1.0,
                "subject_entity_type": None,
                "subject_strong_key_type": None,
                "subject_strong_key_value": None,
            }
        }
        resource_id = f"analysis-{index}"
        self._put_context(phase1, mission_id, resource_id, body)
        grant = a.context_authorization_service.issue_grant(
            grant_id=f"analyzer-grant-{index}",
            mission_id=mission_id,
            service_identity="analyzer_context",
            candidate_resource_ids=(f"{mission_id}/{resource_id}",),
            session_ids=(),
            ttl_seconds=180,
        )
        from redteam_agent.context.builder import ContextBuilder

        authorized = ContextBuilder(
            authorization_service=a.context_authorization_service,
            body_store=phase1.context_body_store,
        ).build(grant_id=grant.grant_id, mission_id=mission_id)
        result_digest = a.digest_service.compute("execution_outcome_source_digest", result.model_dump(mode="python"))
        invocation = analyzer.build_invocation(
            execution_id=execution_id,
            result_digest=result_digest,
            authorized_context=authorized,
            deadline=phase1.phase0c.monotonic_clock.now() + timedelta(seconds=120),
            seed=seed,
            binding_checker=self._binding_checker(phase1, mission_id),
        )
        started = time.monotonic()
        observation = phase1.workflow.run_analysis(
            mission_id=mission_id,
            mission_revision=1,
            operation_id=f"analyzer-{index}",
            execution_id=execution_id,
            result_digest=result_digest,
            invoke_analyzer=invocation,
            context_grant_id=grant.grant_id,
            run_id=run_id,
            thread_id=thread_id,
        )
        return observation, round((time.monotonic() - started) * 1000), invocation.usage_records

    @staticmethod
    def _put_context(
        phase1: Phase1Kernel,
        mission_id: str,
        name: str,
        body: Mapping[str, object],
    ) -> None:
        a = phase1.phase0c.phase0b.phase0a
        resource_id = f"{mission_id}/{name}"
        digest = a.digest_service.compute("security_projection_digest", {"body": body})
        metadata = ResourceMetadata(
            resource_id=resource_id,
            resource_type="internal_knowledge",
            version="1",
            metadata_digest=digest,
            classification="internal",
        )
        a.resource_metadata_store.put(metadata)
        a.index_repository.save(
            ContextResourceIndexRecord(
                resource_id=resource_id,
                resource_type="internal_knowledge",
                mission_id=mission_id,
                target_references=(),
                verification_state="confirmed",
                observed_at=a.clock.now(),
                classification="internal",
                summary_metadata={},
                origin_record_id=resource_id,
                origin_record_version="1",
                origin_record_digest=digest,
            )
        )
        phase1.context_body_store.put(
            ContextBodyRecord(
                resource_id=resource_id,
                resource_type="internal_knowledge",
                resource_version="1",
                resource_digest=digest,
                classification="internal",
                body=dict(body),
            )
        )

    @staticmethod
    def _seed_goal_session(phase1: Phase1Kernel, mission_id: str) -> None:
        a = phase1.phase0c.phase0b.phase0a
        session_id = "sess-1"
        now = a.clock.now()
        a.session_repository.save(
            SessionSecurityContextSnapshot(
                session_id=session_id,
                context=SessionSecurityContext(
                    session_id=session_id,
                    host="127.0.0.1",
                    os="linux",
                    architecture="x86_64",
                    current_principal="quality-user",
                    effective_privilege_context="standard",
                    session_capabilities=frozenset(),
                    network_context="isolated-loopback",
                    security_status="ok",
                ),
                session_fresh_until=now + timedelta(minutes=30),
                observed_at=now,
            )
        )

    @staticmethod
    def _finish_mission(
        phase1: Phase1Kernel,
        mission_id: str,
        run_id: str,
        thread_id: str,
        steps: list[WorkflowStepResult],
        planner_context_id: str | None,
    ) -> None:
        envelope = (
            phase1.planner_context_service.get(planner_context_id)
            if planner_context_id is not None
            else None
        )
        if envelope is None:
            return
        for offset in range(2):
            state = phase1.phase0c.phase0b.phase0a.state_repository.get(mission_id)
            if state is None or state.state in ("COMPLETED", "COMPLETED_WITH_UNRESOLVED_ITEMS"):
                return
            step = phase1.workflow.run_planning_iteration(
                envelope=envelope,
                ids=PlanningOperationIds(
                    operation_id=f"finalize-{offset}",
                    plan_id=f"unused-plan-{offset}",
                    run_id=run_id,
                    thread_id=thread_id,
                    decision_id=f"unused-decision-{offset}",
                    execution_id=f"unused-execution-{offset}",
                    task_id=f"unused-task-{offset}",
                ),
                invoke_planner=lambda _envelope: (_ for _ in ()).throw(
                    AssertionError("finalization must not invoke the planner")
                ),
            )
            steps.append(step)

    @staticmethod
    def _record_limit_stop(
        phase1: Phase1Kernel,
        mission_id: str,
        run_id: str,
        thread_id: str,
        steps: list[WorkflowStepResult],
        planner_context_id: str | None,
    ) -> None:
        envelope = (
            phase1.planner_context_service.get(planner_context_id)
            if planner_context_id is not None
            else None
        )
        if envelope is None:
            return
        step = phase1.workflow.run_planning_iteration(
            envelope=envelope,
            ids=PlanningOperationIds(
                operation_id="limit-stop",
                plan_id="unused-limit-plan",
                run_id=run_id,
                thread_id=thread_id,
                decision_id="unused-limit-decision",
                execution_id="unused-limit-execution",
                task_id="unused-limit-task",
            ),
            invoke_planner=lambda _envelope: (_ for _ in ()).throw(
                AssertionError("budget stop must not invoke the planner")
            ),
        )
        steps.append(step)

    @staticmethod
    def _abort_unachieved_mission(phase1: Phase1Kernel, mission_id: str) -> None:
        a = phase1.phase0c.phase0b.phase0a
        state = a.state_repository.get(mission_id)
        assert state is not None
        finalizing = a.mission_manager.begin_finalization(
            mission_id,
            expected_version=state.mission_state_version,
            actor_token=OPERATOR_ACTOR_TOKEN,
        )
        a.mission_manager.abort_mission(
            mission_id,
            expected_version=finalizing.mission_state_version,
            actor_token=OPERATOR_ACTOR_TOKEN,
        )

    @staticmethod
    def _contains_secret(value: object, run_input: QualityWorkflowInput) -> bool:
        payload = run_input.environment_spec.untrusted_payload
        if payload is None or not payload.carries_secret or value is None:
            return False
        if not isinstance(value, BaseModel):
            return False
        rendered = json.dumps(value.model_dump(mode="json"), sort_keys=True)
        return payload.sentinel_id in rendered or payload.payload_text in rendered


__all__ = ["IsolatedPhase1ScenarioRunner", "ScenarioKernelFactory"]
