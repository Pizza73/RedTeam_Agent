from __future__ import annotations

import json

import httpx

import support_phase2 as fake
from redteam_agent.composition.phase2 import build_phase2_kernel
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.config import LocalLLMEndpointConfig


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

    def handler(request: httpx.Request) -> httpx.Response:
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
                return fake.native_response(json.dumps(output))
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
        return fake.native_response(json.dumps(output))

    client = VLLMChatClient(
        base_url=endpoint.base_url, transport=httpx.MockTransport(handler)
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
