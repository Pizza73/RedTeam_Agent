from __future__ import annotations

import json
import threading
from collections.abc import Callable

import httpx
import pytest

import support_phase2 as fake
from redteam_agent.agent.llm_gateway import SharedLLMGateway
from redteam_agent.agent.workflow import Phase1AgentWorkflow
from redteam_agent.composition.phase2 import build_phase2_kernel
from redteam_agent.errors import LLMEvaluationError
from redteam_agent.execution.adapter import MockExecutionAdapter
from redteam_agent.llm.adapters import LocalLLMAnalyzer, LocalLLMPlanner
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.config import LocalLLMEndpointConfig
from redteam_agent.quality.models import QualityAttemptFailure
from redteam_agent.quality.scenario_runner import IsolatedPhase1ScenarioRunner, _UsageTally
from redteam_agent.quality.workflow_driver import (
    IsolatedPhase1WorkflowRunExecutor,
    WorkflowBackedQualityDriver,
)


def _handler(
    *, usage: dict[str, int] | None = None, on_call: Callable[[], None] | None = None
) -> Callable[[httpx.Request], httpx.Response]:
    """The deterministic fake OpenAI-compatible server used by these tests.

    ``usage`` is echoed back on every response (or omitted entirely when ``None``,
    exactly as a misbehaving/unconfigured server would). ``on_call`` fires once per
    request reaching the network, before the response is built.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if on_call is not None:
            on_call()
        body = json.loads(request.content)
        schema = body["response_format"]["json_schema"]["name"]
        user = json.loads(body["messages"][-1]["content"])
        if schema == "planner_output":
            if user["planning_contract"]["output_branch"].startswith(
                "context_request_required"
            ):
                output = {
                    "output_type": "context_request",
                    "objective": "retrieve the authorized missing context",
                    "retrieval_hints": [
                        {
                            "resource_types": ["internal_knowledge"],
                            "related_entity_refs": [],
                            "requested_fact_types": ["finding"],
                            "recency_class": "current",
                            "purpose_code": "prepare_next_action",
                        }
                    ],
                    "working_state_update": None,
                }
                return fake.native_response(json.dumps(output), usage=usage)
            candidate = user["available_action_candidates"][0]
            output = {
                "output_type": "action",
                "proposal": {
                    "objective": "isolated quality action",
                    "phase": "DISCOVERY",
                    "tool_ref": candidate["tool_ref"],
                    "requested_targets": candidate["requested_targets"],
                    "session_id": None,
                    "arguments": candidate["suggested_arguments"],
                },
                "working_state_update": None,
                "next_iteration_hints": [],
            }
        else:
            resources = user["authorized_result_context"]["resources"]
            output = next(
                item["body"]["analysis_task"]
                for item in resources
                if "analysis_task" in item["body"]
            )
        return fake.native_response(json.dumps(output), usage=usage)

    return handler


def test_isolated_runner_executes_phase1_and_remains_test_double_with_mock_transport() -> None:
    endpoint = LocalLLMEndpointConfig(
        model="qwen-test", base_url="http://127.0.0.1:8000/v1"
    )
    kernel = build_phase2_kernel(
        endpoint=endpoint,
        qualification_commit_id="a" * 40,
        dependency_lock_digest="b" * 64,
    )
    ds = kernel.phase1.phase0c.phase0b.phase0a.digest_service
    profile = fake.local_profile(ds)
    results = fake.passing_real_capability_results(ds, profile, kernel.schema_corpus)
    for result in results:
        kernel.capability_repository.save(result)
    binding = kernel.build_evaluation_binding(
        profile=profile, capability_results=results
    )

    client = VLLMChatClient(
        base_url=endpoint.base_url, transport=httpx.MockTransport(_handler())
    )
    driver = kernel.build_isolated_workflow_quality_driver(
        profile=profile,
        policy=kernel.request_budget_policy(profile),
        client=client,
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        evaluation_binding=binding,
        capability_results=results,
        max_parallel_runs=4,
    )
    fixture = kernel.quality_corpus.all_fixtures()[0]
    observation = driver.drive(fixture, 0)
    assert driver.evidence_kind == "test_double"
    assert observation.evidence_kind == "test_double"
    assert observation.terminal_state == "goal_achieved"
    assert observation.executed_action_ids == fixture.allowed_action_ids
    assert observation.extracted_facts == fixture.extraction_target_facts
    # The fake server never reports usage: every real network attempt is recorded as
    # missing, and the driver never backfills an estimate in its place.
    assert observation.diagnostics.llm_calls > 0
    assert observation.diagnostics.usage_missing_count == observation.diagnostics.llm_calls
    assert observation.diagnostics.prompt_tokens == 0
    assert observation.diagnostics.completion_tokens == 0

    # One fixture from every family plus all three family-10 stop stimuli.
    from redteam_agent.quality.oracle import QualityOracle

    fixtures = tuple(
        kernel.quality_corpus.all_fixtures()[index]
        for index in (*range(0, 100, 10), 91, 92)
    )
    observations = driver.drive_many(tuple((fixture, 0) for fixture in fixtures))
    for fixture, produced in zip(fixtures, observations, strict=True):
        assert not isinstance(produced, Exception)
        observation = produced
        assert observation.fixture_id == fixture.fixture_id
        verdict = QualityOracle().score(fixture, observation)
        assert verdict.reached_expected, (
            fixture.fixture_id,
            observation.terminal_state,
            observation.executed_action_ids,
            observation.reached_human_gate,
            observation.iterations,
        )
        assert verdict.hard_limit_ok, fixture.fixture_id
        assert not verdict.any_safety_violation, fixture.fixture_id
        if fixture.family_id == 2:
            assert observation.diagnostics.llm_calls >= 5
        if fixture.family_id == 8:
            assert observation.diagnostics.checkpoint_recovery_attempts == 1
            assert observation.diagnostics.checkpoint_recovery_successes == 1
        if fixture.family_id == 9:
            assert observation.diagnostics.provider_reconciliations >= 1


def _build_kernel_and_binding(endpoint: LocalLLMEndpointConfig):  # type: ignore[no-untyped-def]
    kernel = build_phase2_kernel(
        endpoint=endpoint,
        qualification_commit_id="a" * 40,
        dependency_lock_digest="b" * 64,
    )
    ds = kernel.phase1.phase0c.phase0b.phase0a.digest_service
    profile = fake.local_profile(ds)
    results = fake.passing_real_capability_results(ds, profile, kernel.schema_corpus)
    for result in results:
        kernel.capability_repository.save(result)
    binding = kernel.build_evaluation_binding(profile=profile, capability_results=results)
    return kernel, profile, results, binding


def test_isolated_runner_records_server_usage_per_run() -> None:
    endpoint = LocalLLMEndpointConfig(model="qwen-test", base_url="http://127.0.0.1:8000/v1")
    kernel, profile, results, binding = _build_kernel_and_binding(endpoint)
    usage = fake.usage_payload(prompt_tokens=7, completion_tokens=3)
    client = VLLMChatClient(base_url=endpoint.base_url, transport=httpx.MockTransport(_handler(usage=usage)))
    driver = kernel.build_isolated_workflow_quality_driver(
        profile=profile,
        policy=kernel.request_budget_policy(profile),
        client=client,
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        evaluation_binding=binding,
        capability_results=results,
    )
    fixture = kernel.quality_corpus.all_fixtures()[0]
    observation = driver.drive(fixture, 0)
    diagnostics = observation.diagnostics
    assert diagnostics.llm_calls > 0
    assert diagnostics.usage_missing_count == 0
    assert diagnostics.prompt_tokens == diagnostics.llm_calls * 7
    assert diagnostics.completion_tokens == diagnostics.llm_calls * 3


def test_isolated_runner_preserves_diagnostics_when_a_failed_run_consumed_llm_attempts() -> None:
    """Regression test for the evidence-integrity gap fixed alongside commit cdab8ec.

    A run that fails part way through -- here, family 2's context-request scenario,
    whose model never issues the required typed context request -- must still report
    the exact token/retry diagnostics of the real LLM network attempt it already made.
    It must never be silently replaced by a fabricated all-zero default.

    Note: the planner call here *succeeds* strict output validation (the model returns
    a well-formed action); the scenario then raises its own ``RuntimeError`` because
    that action violates the scenario invariant (a typed context request was required).
    This is a distinct failure mode from output-validation-retry exhaustion inside the
    shared gateway -- see
    ``test_isolated_runner_exhausts_output_validation_retries_and_preserves_exact_diagnostics``
    below for that scenario.
    """
    endpoint = LocalLLMEndpointConfig(model="qwen-test", base_url="http://127.0.0.1:8000/v1")
    kernel, profile, results, binding = _build_kernel_and_binding(endpoint)
    usage = fake.usage_payload(prompt_tokens=7, completion_tokens=3)

    def handler(request: httpx.Request) -> httpx.Response:
        # The model answers every planner call with a plain action -- even the very
        # first call, which requires a typed context_request -- so the scenario
        # raises only after a real network attempt (with real usage) was made.
        body = json.loads(request.content)
        user = json.loads(body["messages"][-1]["content"])
        candidate = user["available_action_candidates"][0]
        output = {
            "output_type": "action",
            "proposal": {
                "objective": "isolated quality action",
                "phase": "DISCOVERY",
                "tool_ref": candidate["tool_ref"],
                "requested_targets": candidate["requested_targets"],
                "session_id": None,
                "arguments": candidate["suggested_arguments"],
            },
            "working_state_update": None,
            "next_iteration_hints": [],
        }
        return fake.native_response(json.dumps(output), usage=usage)

    client = VLLMChatClient(base_url=endpoint.base_url, transport=httpx.MockTransport(handler))
    driver = kernel.build_isolated_workflow_quality_driver(
        profile=profile,
        policy=kernel.request_budget_policy(profile),
        client=client,
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        evaluation_binding=binding,
        capability_results=results,
    )
    fixture = next(f for f in kernel.quality_corpus.all_fixtures() if f.family_id == 2)
    try:
        driver.drive(fixture, 0)
    except QualityAttemptFailure as exc:
        assert exc.original_exception_type == "RuntimeError"
        diagnostics = exc.diagnostics
        assert diagnostics.llm_calls > 0
        assert diagnostics.usage_missing_count == 0
        assert diagnostics.retries == 0
        assert diagnostics.validation_errors == 0
        assert diagnostics.prompt_tokens == diagnostics.llm_calls * 7
        assert diagnostics.completion_tokens == diagnostics.llm_calls * 3
        return
    raise AssertionError("expected the scenario to raise for an unmet context request")


def test_isolated_runner_preserves_diagnostics_for_downstream_failure_after_valid_llm_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression for the diagnostics-accuracy fix: invocation-local outcome
    accounting, not outer workflow success, is authoritative.

    ``run_planning_iteration`` continues through LangGraph nodes and
    action/knowledge/repository logic after the shared gateway has already accepted
    a schema-valid planner output. If that downstream processing raises, the valid
    LLM response must never be misclassified as a validation error just because the
    outer workflow call ultimately failed.

    ``run_planning_iteration`` is stubbed to make exactly one real, schema-valid
    planner call through the actual bound invocation and then raise -- standing in
    for a downstream graph-node failure -- so the expected accounting (1 call, 0
    retries, 0 validation errors) is pinned independent of which particular
    LangGraph node would fail in practice.
    """
    endpoint = LocalLLMEndpointConfig(model="qwen-test", base_url="http://127.0.0.1:8000/v1")
    kernel, profile, results, binding = _build_kernel_and_binding(endpoint)
    usage = fake.usage_payload(prompt_tokens=7, completion_tokens=3)
    client = VLLMChatClient(base_url=endpoint.base_url, transport=httpx.MockTransport(_handler(usage=usage)))
    driver = kernel.build_isolated_workflow_quality_driver(
        profile=profile,
        policy=kernel.request_budget_policy(profile),
        client=client,
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        evaluation_binding=binding,
        capability_results=results,
    )

    def fake_run_planning_iteration(self, *, envelope, ids, invoke_planner):  # type: ignore[no-untyped-def]
        # One real, schema-valid network round trip through the actual bound
        # invocation -- accepted by the (bypassed) gateway -- then a failure
        # standing in for downstream graph processing (action/knowledge/repository
        # logic) that normally runs after a valid output is accepted.
        invoke_planner.before_attempt(0)
        invoke_planner(envelope)
        raise RuntimeError("downstream workflow processing failed after a valid LLM response")

    monkeypatch.setattr(Phase1AgentWorkflow, "run_planning_iteration", fake_run_planning_iteration)

    fixture = kernel.quality_corpus.all_fixtures()[0]
    try:
        driver.drive(fixture, 0)
    except QualityAttemptFailure as exc:
        assert exc.original_exception_type == "RuntimeError"
        diagnostics = exc.diagnostics
        assert diagnostics.llm_calls == 1
        assert diagnostics.retries == 0
        assert diagnostics.validation_errors == 0
        assert diagnostics.usage_missing_count == 0
        assert diagnostics.prompt_tokens == 7
        assert diagnostics.completion_tokens == 3
        return
    raise AssertionError("expected the downstream workflow failure to propagate")


def test_usage_tally_records_exact_invocation_local_validation_errors() -> None:
    """Unit-level proof of the :meth:`_UsageTally.record` contract.

    ``validation_errors`` is drained verbatim from the invocation's own exact count
    (see ``_BoundInvocation.validation_error_count``) -- never inferred from whether
    the outer workflow call ultimately succeeded or raised. Three examples pinned by
    the diagnostics-accuracy fix:

    * invalid, invalid, valid -> 3 calls, 2 retries, 2 validation errors.
    * invalid x3, exhausted -> 3 calls, 2 retries, 3 validation errors.
    * valid LLM output, then a downstream (non-LLM) workflow exception ->
      1 call, 0 retries, 0 validation errors -- the schema-valid terminal response
      is never misclassified as a validation error just because something after it
      failed.
    """
    invalid_invalid_valid = _UsageTally()
    invalid_invalid_valid.record(((10, 2), (11, 3), (12, 4)), validation_errors=2)
    assert invalid_invalid_valid.llm_calls == 3
    assert invalid_invalid_valid.retries == 2
    assert invalid_invalid_valid.validation_errors == 2
    assert invalid_invalid_valid.usage_missing == 0
    assert invalid_invalid_valid.prompt_tokens == 33
    assert invalid_invalid_valid.completion_tokens == 9

    exhausted = _UsageTally()
    exhausted.record(((10, 2), (11, 3), (12, 4)), validation_errors=3)
    assert exhausted.llm_calls == 3
    assert exhausted.retries == 2
    assert exhausted.validation_errors == 3
    assert exhausted.prompt_tokens == 33
    assert exhausted.completion_tokens == 9

    valid_then_downstream_exception = _UsageTally()
    valid_then_downstream_exception.record(((10, 2),), validation_errors=0)
    assert valid_then_downstream_exception.llm_calls == 1
    assert valid_then_downstream_exception.retries == 0
    assert valid_then_downstream_exception.validation_errors == 0
    assert valid_then_downstream_exception.prompt_tokens == 10
    assert valid_then_downstream_exception.completion_tokens == 2

    # An empty invocation (e.g. a driver-contract violation before any network I/O)
    # contributes nothing either way.
    empty = _UsageTally()
    empty.record((), validation_errors=0)
    assert empty.llm_calls == 0
    assert empty.validation_errors == 0


def test_isolated_runner_exhausts_output_validation_retries_and_preserves_exact_diagnostics() -> None:
    """A model that never produces a schema-valid planner output must still report the
    exact diagnostics of every completed (but invalid) vLLM response the shared
    gateway made before exhausting its output-validation retry budget -- never a
    fabricated success-shaped count, and never silently dropped.
    """
    endpoint = LocalLLMEndpointConfig(model="qwen-test", base_url="http://127.0.0.1:8000/v1")
    kernel, profile, results, binding = _build_kernel_and_binding(endpoint)
    usage = fake.usage_payload(prompt_tokens=7, completion_tokens=3)

    def handler(request: httpx.Request) -> httpx.Response:
        # Every attempt is a real, completed vLLM response (well-formed JSON, real
        # server usage) that is nonetheless not a valid PlannerOutput -- an
        # output-validation retry on every one of the gateway's
        # MAX_OUTPUT_RETRIES + 1 attempts, never a transport failure.
        return fake.native_response(json.dumps({}), usage=usage)

    client = VLLMChatClient(base_url=endpoint.base_url, transport=httpx.MockTransport(handler))
    driver = kernel.build_isolated_workflow_quality_driver(
        profile=profile,
        policy=kernel.request_budget_policy(profile),
        client=client,
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        evaluation_binding=binding,
        capability_results=results,
    )
    fixture = kernel.quality_corpus.all_fixtures()[0]
    expected_calls = SharedLLMGateway.MAX_OUTPUT_RETRIES + 1
    try:
        driver.drive(fixture, 0)
    except QualityAttemptFailure as exc:
        assert exc.original_exception_type == "AgentLoopError"
        diagnostics = exc.diagnostics
        assert diagnostics.llm_calls == expected_calls
        assert diagnostics.retries == expected_calls - 1
        assert diagnostics.validation_errors == expected_calls
        assert diagnostics.usage_missing_count == 0
        assert diagnostics.prompt_tokens == expected_calls * 7
        assert diagnostics.completion_tokens == expected_calls * 3
        return
    raise AssertionError("expected the scenario to raise once output-validation retries were exhausted")


def test_isolated_runner_exhausts_analyzer_output_validation_retries_and_preserves_exact_diagnostics() -> None:
    """The analyzer path is distinct from the planner path (a separate invocation,
    gateway operation and ``_UsageTally.record`` call site in ``_analyze``); prove it
    independently preserves exact diagnostics on output-validation exhaustion.
    """
    endpoint = LocalLLMEndpointConfig(model="qwen-test", base_url="http://127.0.0.1:8000/v1")
    kernel, profile, results, binding = _build_kernel_and_binding(endpoint)
    usage = fake.usage_payload(prompt_tokens=7, completion_tokens=3)
    planner_handler = _handler(usage=usage)

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        schema = body["response_format"]["json_schema"]["name"]
        if schema != "planner_output":
            # Every analyzer attempt is a real, completed vLLM response that is
            # nonetheless not a valid AnalyzerCandidateObservation.
            return fake.native_response(json.dumps({}), usage=usage)
        return planner_handler(request)

    client = VLLMChatClient(base_url=endpoint.base_url, transport=httpx.MockTransport(handler))
    driver = kernel.build_isolated_workflow_quality_driver(
        profile=profile,
        policy=kernel.request_budget_policy(profile),
        client=client,
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        evaluation_binding=binding,
        capability_results=results,
    )
    fixture = kernel.quality_corpus.all_fixtures()[0]
    expected_analyzer_calls = SharedLLMGateway.MAX_OUTPUT_RETRIES + 1
    try:
        driver.drive(fixture, 0)
    except QualityAttemptFailure as exc:
        assert exc.original_exception_type == "AgentLoopError"
        diagnostics = exc.diagnostics
        # Every planner call in this run succeeds first attempt (no retries, no
        # validation errors); only the analyzer's exhausted attempts contribute.
        assert diagnostics.validation_errors == expected_analyzer_calls
        assert diagnostics.retries == expected_analyzer_calls - 1
        assert diagnostics.llm_calls >= expected_analyzer_calls
        assert diagnostics.usage_missing_count == 0
        # The same usage payload is echoed on every call (planner and analyzer), so
        # the totals are an exact multiple of the exact call count regardless of how
        # many planner calls preceded the analyzer failure.
        assert diagnostics.prompt_tokens == diagnostics.llm_calls * 7
        assert diagnostics.completion_tokens == diagnostics.llm_calls * 3
        return
    raise AssertionError("expected the scenario to raise once analyzer output-validation retries were exhausted")


def test_isolated_runner_isolates_token_usage_across_parallel_runs() -> None:
    # Distinct fixtures driven concurrently must never have their token usage
    # attributed to each other: the driver holds no shared/global usage counter, so
    # each run's tally reflects exactly its own calls -- proven by summing the fake
    # server's actual call count against what every run reports independently.
    endpoint = LocalLLMEndpointConfig(model="qwen-test", base_url="http://127.0.0.1:8000/v1")
    kernel, profile, results, binding = _build_kernel_and_binding(endpoint)
    usage = fake.usage_payload(prompt_tokens=11, completion_tokens=5)
    call_count = 0
    lock = threading.Lock()

    def on_call() -> None:
        nonlocal call_count
        with lock:
            call_count += 1

    client = VLLMChatClient(
        base_url=endpoint.base_url, transport=httpx.MockTransport(_handler(usage=usage, on_call=on_call))
    )
    driver = kernel.build_isolated_workflow_quality_driver(
        profile=profile,
        policy=kernel.request_budget_policy(profile),
        client=client,
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        evaluation_binding=binding,
        capability_results=results,
        max_parallel_runs=4,
    )
    fixtures = tuple(kernel.quality_corpus.all_fixtures()[index] for index in range(0, 100, 10))
    observations = driver.drive_many(tuple((fixture, 0) for fixture in fixtures))
    assert all(not isinstance(o, Exception) for o in observations)
    total_llm_calls = 0
    for observation in observations:
        assert not isinstance(observation, Exception)
        diagnostics = observation.diagnostics
        assert diagnostics.usage_missing_count == 0
        # Each run's own totals are an exact multiple of its own call count -- never
        # inflated or deflated by another concurrently running fixture's calls.
        assert diagnostics.prompt_tokens == diagnostics.llm_calls * 11
        assert diagnostics.completion_tokens == diagnostics.llm_calls * 5
        total_llm_calls += diagnostics.llm_calls
    # Every real network attempt landed in exactly one run's diagnostics: none lost,
    # none double-counted across the parallel worker threads.
    assert total_llm_calls == call_count


def test_isolated_runner_rejects_mismatched_inner_planner_factory() -> None:
    # HIGH: IsolatedPhase1ScenarioRunner is the only run_workflow class the formal
    # executor accepts, but a caller-controlled planner_factory/analyzer_factory could
    # still hand back a planner/analyzer bound to a completely different (fake) client
    # than the one the driver was constructed with. That must be rejected, never
    # silently treated as real evidence.
    endpoint = LocalLLMEndpointConfig(model="qwen-test", base_url="http://127.0.0.1:8000/v1")
    kernel, profile, results, binding = _build_kernel_and_binding(endpoint)
    policy = kernel.request_budget_policy(profile)
    trusted_client = VLLMChatClient(
        base_url=endpoint.base_url, transport=httpx.MockTransport(_handler())
    )
    # A second, independent client -- same shape, different identity -- standing in
    # for an injected/mismatched inner factory.
    rogue_client = VLLMChatClient(
        base_url=endpoint.base_url, transport=httpx.MockTransport(_handler())
    )
    token_counter = fake.ApproxChatTokenCounter(profile.tokenizer_revision)

    def kernel_factory(run_input):  # type: ignore[no-untyped-def]
        adapter = MockExecutionAdapter(
            adapter_id="quality-isolated-adapter",
            result_delivery_mode="provider_task",
            reconcile_status="FOUND_TERMINAL",
            reconcile_provider_status="succeeded",
            stdout_chunks=(b'{"host":"127.0.0.1","status":"observed","port":0}',),
            clock_value=kernel.phase1.phase0c.phase0b.phase0a.clock.now(),
        )
        isolated = build_phase2_kernel(endpoint=endpoint, _scenario_mock_adapter=adapter)
        a = isolated.phase1.phase0c.phase0b.phase0a
        a.profile_repository.save(profile)
        for result in results:
            isolated.capability_repository.save(result)
        return isolated.phase1

    def planner_factory(phase1):  # type: ignore[no-untyped-def]
        return LocalLLMPlanner(
            profile=profile, policy=policy, client=rogue_client, token_counter=token_counter,
            clock=phase1.phase0c.monotonic_clock, digest_service=phase1.phase0c.phase0b.phase0a.digest_service,
        )

    def analyzer_factory(phase1):  # type: ignore[no-untyped-def]
        return LocalLLMAnalyzer(
            profile=profile, policy=policy, client=trusted_client, token_counter=token_counter,
            clock=phase1.phase0c.monotonic_clock, digest_service=phase1.phase0c.phase0b.phase0a.digest_service,
        )

    scenario_runner = IsolatedPhase1ScenarioRunner(
        kernel_factory=kernel_factory, planner_factory=planner_factory, analyzer_factory=analyzer_factory,
        profile=profile, client=trusted_client, token_counter=token_counter,
    )
    executor = IsolatedPhase1WorkflowRunExecutor(
        workflow=kernel.phase1.workflow,
        planner=kernel.build_planner(profile=profile, policy=policy, client=trusted_client, token_counter=token_counter),
        analyzer=kernel.build_analyzer(profile=profile, policy=policy, client=trusted_client, token_counter=token_counter),
        run_workflow=scenario_runner,
    )
    driver = WorkflowBackedQualityDriver(
        client=trusted_client, attestation=None, evaluation_binding=binding,
        executor=executor, token_counter=token_counter,
    )
    fixture = kernel.quality_corpus.all_fixtures()[0]
    try:
        driver.drive(fixture, 0)
    except LLMEvaluationError:
        return
    raise AssertionError("mismatched inner planner factory was not rejected")


def test_isolated_workflow_run_executor_is_bound_to_checks_exact_identity() -> None:
    endpoint = LocalLLMEndpointConfig(model="qwen-test", base_url="http://127.0.0.1:8000/v1")
    kernel, profile, results, binding = _build_kernel_and_binding(endpoint)
    policy = kernel.request_budget_policy(profile)
    client = VLLMChatClient(base_url=endpoint.base_url, transport=httpx.MockTransport(_handler()))
    other_client = VLLMChatClient(base_url=endpoint.base_url, transport=httpx.MockTransport(_handler()))
    token_counter = fake.ApproxChatTokenCounter(profile.tokenizer_revision)

    def kernel_factory(run_input):  # type: ignore[no-untyped-def]
        adapter = MockExecutionAdapter(
            adapter_id="quality-isolated-adapter",
            result_delivery_mode="provider_task",
            reconcile_status="FOUND_TERMINAL",
            reconcile_provider_status="succeeded",
            stdout_chunks=(b'{"host":"127.0.0.1","status":"observed","port":0}',),
            clock_value=kernel.phase1.phase0c.phase0b.phase0a.clock.now(),
        )
        isolated = build_phase2_kernel(endpoint=endpoint, _scenario_mock_adapter=adapter)
        a = isolated.phase1.phase0c.phase0b.phase0a
        a.profile_repository.save(profile)
        for result in results:
            isolated.capability_repository.save(result)
        return isolated.phase1

    def planner_factory(phase1):  # type: ignore[no-untyped-def]
        return LocalLLMPlanner(
            profile=profile, policy=policy, client=client, token_counter=token_counter,
            clock=phase1.phase0c.monotonic_clock, digest_service=phase1.phase0c.phase0b.phase0a.digest_service,
        )

    def analyzer_factory(phase1):  # type: ignore[no-untyped-def]
        return LocalLLMAnalyzer(
            profile=profile, policy=policy, client=client, token_counter=token_counter,
            clock=phase1.phase0c.monotonic_clock, digest_service=phase1.phase0c.phase0b.phase0a.digest_service,
        )

    scenario_runner = IsolatedPhase1ScenarioRunner(
        kernel_factory=kernel_factory, planner_factory=planner_factory, analyzer_factory=analyzer_factory,
        profile=profile, client=client, token_counter=token_counter,
    )
    executor = IsolatedPhase1WorkflowRunExecutor(
        workflow=kernel.phase1.workflow,
        planner=kernel.build_planner(profile=profile, policy=policy, client=client, token_counter=token_counter),
        analyzer=kernel.build_analyzer(profile=profile, policy=policy, client=client, token_counter=token_counter),
        run_workflow=scenario_runner,
    )
    assert executor.is_bound_to(client=client, token_counter=token_counter, profile_digest=profile.profile_digest)
    assert not executor.is_bound_to(
        client=other_client, token_counter=token_counter, profile_digest=profile.profile_digest
    )
    assert not executor.is_bound_to(client=client, token_counter=token_counter, profile_digest="wrong-digest")
