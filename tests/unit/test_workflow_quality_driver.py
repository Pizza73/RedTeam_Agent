from __future__ import annotations

import support_phase2 as fake
from redteam_agent.composition.phase2 import build_phase2_kernel
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.config import LocalLLMEndpointConfig
from redteam_agent.quality.workflow_driver import WorkflowRunTrace


def _driver():
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
    seen = []

    def run(workflow, planner, analyzer, run_input, attempt_index, seed):  # type: ignore[no-untyped-def]
        seen.append((workflow, planner, analyzer, run_input.fixture_id, attempt_index, seed))
        return WorkflowRunTrace(
            steps=(),
            final_mission_state="COMPLETED",
            goal_status="achieved",
            iterations=2,
            recovery_reconciled=False,
            duplicate_dispatch_count=0,
            extracted_facts=run_input.environment_spec.analyzer_observations[:1]
            and (run_input.environment_spec.analyzer_observations[0].fact_id,),
            confirmed_facts=(),
            secret_leaked=False,
        )

    driver = kernel.build_workflow_quality_driver(
        profile=profile,
        policy=kernel.request_budget_policy(profile),
        client=VLLMChatClient(
            base_url=endpoint.base_url,
            transport=fake.transport_returning(fake.native_response("{}")),
        ),
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        evaluation_binding=binding,
        run_workflow=run,
    )
    return kernel, driver, seen


def test_workflow_driver_uses_phase1_workflow_and_is_test_double_with_injected_transport() -> None:
    kernel, driver, seen = _driver()
    fixture = kernel.quality_corpus.all_fixtures()[0]
    observation = driver.drive(fixture, 0)
    assert seen[0][0] is kernel.phase1.workflow
    assert observation.evidence_kind == "test_double"
    assert driver.evidence_kind == "test_double"


def test_oracle_expectations_do_not_change_workflow_projection() -> None:
    kernel, driver, _ = _driver()
    fixture = kernel.quality_corpus.all_fixtures()[0]
    changed = fixture.model_copy(
        update={
            "expected_terminal": "security_stop",
            "goal_expected_achieved": False,
            "expected_human_gate": True,
        }
    )
    assert driver.drive(fixture, 0) == driver.drive(changed, 0)
