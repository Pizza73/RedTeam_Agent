from __future__ import annotations

import json
from pathlib import Path

import pytest

from automation.run_phase_loop import (
    UntrustedEvidenceError,
    marker_payloads,
    select_evidence_action,
    select_finding_key,
    strict_json_loads,
    validate_implementation_request,
    validate_review_result,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40


def load_schema(name: str) -> dict[str, object]:
    path = REPO_ROOT / "automation" / "schemas" / name
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def review_result(*, verdict: str = "PASS") -> dict[str, object]:
    findings: list[dict[str, object]] = []
    if verdict == "CHANGES_REQUESTED":
        findings.append(
            {
                "id": "FINDING-1",
                "severity": "HIGH",
                "requirement_id": "SAFE-001",
                "evidence": "Fail-closed regression evidence",
                "required_fix": "Restore the deny path",
                "retest": ["pytest tests/security"],
            }
        )
    return {
        "schema_version": "1.0",
        "phase": "phase-0a",
        "reviewed_sha": HEAD_SHA,
        "base_sha": BASE_SHA,
        "verdict": verdict,
        "summary": "Independent review completed",
        "findings": findings,
        "required_checks": [
            {"name": "tests (3.12)", "status": "PASS"},
            {"name": "tests (3.14)", "status": "PASS"},
            {"name": "quality", "status": "PASS"},
            {"name": "governance-integrity", "status": "PASS"},
        ],
    }


def implementation_request() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "action": "IMPLEMENT_PHASE",
        "trigger": "PHASE_START",
        "phase": "phase-0a",
        "head_sha": HEAD_SHA,
        "phase_prompt": "prompts/phases/phase-0a-security-fix.md",
    }


def test_nested_duplicate_marker_key_is_rejected() -> None:
    with pytest.raises(UntrustedEvidenceError, match="duplicate JSON key"):
        strict_json_loads('{"review":{"phase":"phase-0a","phase":"phase-1"}}')


def test_marker_parser_returns_each_named_marker() -> None:
    body = 'noise <!-- result {"value":1} --> more <!-- result\n{"value":2}\n--> trailing'

    assert marker_payloads(body, "result") == [{"value": 1}, {"value": 2}]


def test_review_result_binds_phase_head_and_base() -> None:
    validate_review_result(
        review_result(),
        schema=load_schema("review-result.schema.json"),
        phase="phase-0a",
        reviewed_sha=HEAD_SHA,
        base_sha=BASE_SHA,
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("phase", "phase-0b", "review phase"),
        ("reviewed_sha", "c" * 40, "reviewed SHA"),
        ("base_sha", "d" * 40, "review base SHA"),
    ],
)
def test_stale_review_result_is_rejected(field: str, value: str, message: str) -> None:
    payload = review_result()
    payload[field] = value

    with pytest.raises(UntrustedEvidenceError, match=message):
        validate_review_result(
            payload,
            schema=load_schema("review-result.schema.json"),
            phase="phase-0a",
            reviewed_sha=HEAD_SHA,
            base_sha=BASE_SHA,
        )


def test_review_missing_required_check_is_rejected() -> None:
    payload = review_result()
    payload["required_checks"] = [{"name": "quality", "status": "PASS"}]

    with pytest.raises(UntrustedEvidenceError, match="every required check"):
        validate_review_result(
            payload,
            schema=load_schema("review-result.schema.json"),
            phase="phase-0a",
            reviewed_sha=HEAD_SHA,
            base_sha=BASE_SHA,
        )


def test_implementation_request_binds_phase_head_and_prompt() -> None:
    validate_implementation_request(
        implementation_request(),
        schema=load_schema("implementation-request.schema.json"),
        phase="phase-0a",
        head_sha=HEAD_SHA,
        phase_prompt="prompts/phases/phase-0a-security-fix.md",
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("phase", "phase-0b", "implementation phase"),
        ("head_sha", "c" * 40, "implementation SHA"),
        ("phase_prompt", "prompts/phases/phase-0b.md", "wrong phase prompt"),
    ],
)
def test_stale_implementation_request_is_rejected(field: str, value: str, message: str) -> None:
    payload = implementation_request()
    payload[field] = value

    with pytest.raises(UntrustedEvidenceError, match=message):
        validate_implementation_request(
            payload,
            schema=load_schema("implementation-request.schema.json"),
            phase="phase-0a",
            head_sha=HEAD_SHA,
            phase_prompt="prompts/phases/phase-0a-security-fix.md",
        )


def test_implementation_request_with_unknown_field_is_rejected() -> None:
    payload = implementation_request()
    payload["untrusted_override"] = True

    with pytest.raises(UntrustedEvidenceError, match="schema failure"):
        validate_implementation_request(
            payload,
            schema=load_schema("implementation-request.schema.json"),
            phase="phase-0a",
            head_sha=HEAD_SHA,
            phase_prompt="prompts/phases/phase-0a-security-fix.md",
        )


def test_changes_requested_uses_requirement_id_as_stable_key() -> None:
    assert select_finding_key(review_result(verdict="CHANGES_REQUESTED")) == "SAFE-001"


def test_changes_requested_without_stable_key_is_rejected() -> None:
    payload = review_result(verdict="CHANGES_REQUESTED")
    finding = payload["findings"][0]  # type: ignore[index]
    finding["requirement_id"] = "not a stable key"  # type: ignore[index]
    finding["id"] = "also invalid"  # type: ignore[index]

    with pytest.raises(UntrustedEvidenceError, match="stable finding key"):
        select_finding_key(payload)


def test_fix_request_takes_precedence_over_old_ready_marker() -> None:
    assert (
        select_evidence_action(
            request_exists=True,
            ready_exists=True,
            labels=frozenset({"ai-loop", "ai-needs-fix"}),
        )
        == "implementation"
    )


def test_ready_marker_is_reviewed_when_no_implementation_is_pending() -> None:
    assert (
        select_evidence_action(
            request_exists=True,
            ready_exists=True,
            labels=frozenset({"ai-loop", "ai-needs-review"}),
        )
        == "review"
    )
