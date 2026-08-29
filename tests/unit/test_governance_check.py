from __future__ import annotations

import pytest

from scripts.ci.check_governance import (
    GovernanceInputError,
    evaluate_governance,
    is_protected_path,
)


def test_regular_implementation_change_is_allowed() -> None:
    result = evaluate_governance(
        ["src/redteam_agent/policy/engine.py", "tests/security/test_policy.py"],
        {"ai-loop", "phase-0a"},
    )

    assert result.allowed is True
    assert result.protected_paths == ()


@pytest.mark.parametrize(
    "path",
    [
        "AGENTS.md",
        ".github/workflows/ci.yml",
        "automation/phase-plan.json",
        "docs/ai-loop-runbook.md",
        "docs/safety-invariants.md",
        "prompts/phases/phase-0a-security-fix.md",
        "scripts/ci/check_governance.py",
        "scripts/ci/run_phase_gate.sh",
        "scripts/ci/validate_automation.py",
        "pyproject.toml",
        "requirements.lock",
    ],
)
def test_ai_loop_change_to_governance_is_blocked(path: str) -> None:
    result = evaluate_governance([path], {"ai-loop", "phase-0a"})

    assert result.allowed is False
    assert result.protected_paths == (path,)


def test_explicit_human_governance_pull_request_is_allowed() -> None:
    result = evaluate_governance(
        [".github/workflows/ci.yml", "docs/ai-development-loop.md"],
        {"governance-change"},
    )

    assert result.allowed is True
    assert result.protected_paths == (
        ".github/workflows/ci.yml",
        "docs/ai-development-loop.md",
    )
    assert result.reason == (
        "explicit governance-change pull request; manual owner review is required "
        "but not server-enforced"
    )


def test_unlabelled_governance_change_is_blocked() -> None:
    result = evaluate_governance(["automation/phase-plan.json"], set())

    assert result.allowed is False
    assert "governance-change" in result.reason


@pytest.mark.parametrize("path", ["../AGENTS.md", "/AGENTS.md", "docs//requirements.md"])
def test_noncanonical_changed_path_fails_closed(path: str) -> None:
    with pytest.raises(GovernanceInputError):
        is_protected_path(path)
