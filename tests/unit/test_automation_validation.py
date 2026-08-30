from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from scripts.ci.validate_automation import (
    AutomationValidationError,
    strict_json_load,
    validate_automation,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_repository_automation_configuration_is_valid() -> None:
    validate_automation(REPO_ROOT)


def test_nested_duplicate_json_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"outer":{"phase":"phase-0a","phase":"phase-1"}}', encoding="utf-8")

    with pytest.raises(AutomationValidationError, match="duplicate JSON key"):
        strict_json_load(path)


def test_unknown_phase_plan_field_is_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "automation", repo / "automation")
    shutil.copytree(REPO_ROOT / "prompts", repo / "prompts")
    plan_path = repo / "automation" / "phase-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["unexpected"] = True
    plan_path.write_text(json.dumps(plan), encoding="utf-8")

    with pytest.raises(AutomationValidationError, match="schema validation failed"):
        validate_automation(repo)


def test_approved_but_incomplete_provider_gate_is_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "automation", repo / "automation")
    shutil.copytree(REPO_ROOT / "prompts", repo / "prompts")
    gates_path = repo / "automation" / "provider-gates.json"
    gates = json.loads(gates_path.read_text(encoding="utf-8"))
    gates["phase-4"]["approved"] = True
    gates_path.write_text(json.dumps(gates), encoding="utf-8")

    with pytest.raises(AutomationValidationError, match="approved provider gate is incomplete"):
        validate_automation(repo)


def test_phase_gate_uses_fail_closed_native_codex_evidence_chain() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "ai-loop-control.yml").read_text(
        encoding="utf-8"
    )

    for required_control in (
        "ready_reference",
        "review_trigger_reference",
        "codex-native-v1",
        "listEventsForTimeline",
        "listReviewComments",
        "listForIssue",
        "PR head changed while Codex review was running",
        "missing its reviewer thumbs-up reaction",
        "missing retained P0/P1 findings",
        "duplicate JSON key",
        "redteam-base-refresh",
        "target_base_sha",
        "merge_base_commit?.sha === refresh.target_base_sha",
        "Reviewed Phase 0A head is not descended from a trusted base refresh",
        "liveDefaultCommit.sha !== refreshTargetSha",
        "Default branch changed before recording the refreshed Phase 0A gate",
        "Pull request head or phase changed before recording the gate",
    ):
        assert required_control in workflow
    assert "Review evidence must contain exactly one redteam-ai-review marker" not in workflow


def test_phase_gate_has_minimal_permissions_for_pr_state_updates() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "ai-loop-control.yml").read_text(
        encoding="utf-8"
    )
    permissions = workflow.split("\npermissions:\n", maxsplit=1)[1].split(
        "\njobs:\n", maxsplit=1
    )[0]

    assert permissions.strip().splitlines() == [
        "checks: read",
        "  contents: read",
        "  issues: write",
        "  pull-requests: write",
        "  statuses: write",
    ]
    for forbidden_operation in (
        "github.rest.pulls.merge",
        "mergePullRequest",
        "event: 'APPROVE'",
        'event: "APPROVE"',
    ):
        assert forbidden_operation not in workflow


def test_documented_reviewer_login_includes_bot_suffix() -> None:
    runbook = (REPO_ROOT / "docs" / "ai-loop-runbook.md").read_text(encoding="utf-8")

    assert "AI_REVIEWER_LOGIN --body 'chatgpt-codex-connector[bot]'" in runbook


def test_base_refresh_is_sha_bound_and_cannot_merge_the_pull_request() -> None:
    workflow = (
        REPO_ROOT / ".github" / "workflows" / "refresh-ai-loop-base.yml"
    ).read_text(encoding="utf-8")
    runner = (REPO_ROOT / "automation" / "run_phase_loop.py").read_text(encoding="utf-8")

    for required_control in (
        "REFRESH_AI_LOOP_BASE",
        "AI_GATE_APPROVER_LOGIN",
        "source_phase",
        "expected_head_sha",
        "target_base_sha",
        "prior_pass_reference",
        "redteam-base-refresh",
        "setLabels",
        "contains a duplicate JSON key",
        "Reauthorization requires a trusted prior base-refresh marker",
    ):
        assert required_control in workflow or required_control in runner
    permissions = workflow.split("\npermissions:\n", maxsplit=1)[1].split(
        "\njobs:\n", maxsplit=1
    )[0]
    assert permissions.strip().splitlines() == [
        "contents: read",
        "  issues: write",
        "  pull-requests: read",
        "  statuses: write",
    ]
    assert r"while (/\s/.test" in workflow
    assert r"while (/\\s/.test" not in workflow
    assert r"!/[\s,}\]]/.test" in workflow
    assert "pr.base.sha !== targetBaseSha" not in workflow
    assert "contents: write" not in workflow
    assert "update-branch" in runner
    for forbidden_operation in (
        "github.rest.pulls.merge",
        "mergePullRequest",
        "/pulls/{number}/merge",
        "/pulls/3/merge",
    ):
        assert forbidden_operation not in workflow
        assert forbidden_operation not in runner
