from __future__ import annotations

import json
from pathlib import Path

import pytest

from automation.run_phase_loop import (
    MarkerEvidence,
    ReviewEvidence,
    UntrustedEvidenceError,
    canonical_digest,
    evaluate_native_review,
    marker_payloads,
    native_finding_key,
    select_evidence_action,
    select_finding_key,
    strict_json_loads,
    validate_implementation_request,
    validate_review_result,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40
ACTOR_LOGIN = "operator"
REVIEWER_LOGIN = "chatgpt-codex-connector[bot]"
READY_URL = "https://github.com/example/repo/pull/1#issuecomment-ready"
TRIGGER_URL = "https://github.com/example/repo/pull/1#issuecomment-trigger"
NO_FINDINGS_URL = "https://github.com/example/repo/pull/1#issuecomment-no-findings"
REVIEW_URL = "https://github.com/example/repo/pull/1#pullrequestreview-77"


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


def marker(name: str, payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"<!-- {name}\n{encoded}\n-->"


def native_evidence() -> dict[str, object]:
    ready_payload: dict[str, object] = {
        "schema_version": "1.0",
        "phase": "phase-0a",
        "head_sha": HEAD_SHA,
    }
    source = {
        "ready_url": READY_URL,
        "phase": "phase-0a",
        "head_sha": HEAD_SHA,
        "base_sha": BASE_SHA,
    }
    trigger_payload: dict[str, object] = {
        "schema_version": "1.0",
        "kind": "review",
        "phase": "phase-0a",
        "head_sha": HEAD_SHA,
        "source_digest": canonical_digest(source),
    }
    ready_body = marker("redteam-ready-for-review", ready_payload)
    trigger_body = (
        "@codex review\n\n"
        f"Review exact PR HEAD `{HEAD_SHA}` against phase base `{BASE_SHA}`.\n\n"
        f"{marker('redteam-local-codex-trigger', trigger_payload)}"
    )
    pass_body = (
        "Codex Review: Didn't find any major issues. Hooray!\n\n"
        f"**Reviewed commit:** `{HEAD_SHA[:10]}`"
    )
    return {
        "ready": MarkerEvidence(
            payload=ready_payload,
            url=READY_URL,
            author="github-actions[bot]",
            body=ready_body,
        ),
        "comments": [
            {
                "id": 1,
                "html_url": READY_URL,
                "user": {"login": "github-actions[bot]"},
                "created_at": "2026-08-30T00:00:00Z",
                "body": ready_body,
            },
            {
                "id": 2,
                "html_url": TRIGGER_URL,
                "user": {"login": ACTOR_LOGIN},
                "created_at": "2026-08-30T00:01:00Z",
                "body": trigger_body,
            },
            {
                "id": 3,
                "html_url": NO_FINDINGS_URL,
                "user": {"login": REVIEWER_LOGIN},
                "created_at": "2026-08-30T00:02:00Z",
                "body": pass_body,
            },
        ],
        "reviews": [],
        "review_comments": [],
        "reactions": [
            {
                "id": 4,
                "user": {"login": REVIEWER_LOGIN},
                "content": "+1",
                "created_at": "2026-08-30T00:02:04Z",
            }
        ],
        "timeline": [],
    }


def evaluate_fixture(evidence: dict[str, object]) -> ReviewEvidence | None:
    return evaluate_native_review(
        phase="phase-0a",
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        ready=evidence["ready"],  # type: ignore[arg-type]
        actor_login=ACTOR_LOGIN,
        reviewer_login=REVIEWER_LOGIN,
        comments=evidence["comments"],  # type: ignore[arg-type]
        reviews=evidence["reviews"],  # type: ignore[arg-type]
        review_comments=evidence["review_comments"],  # type: ignore[arg-type]
        reactions=evidence["reactions"],  # type: ignore[arg-type]
        timeline=evidence["timeline"],  # type: ignore[arg-type]
    )


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
    finding["requirement_id"] = "not a stable key"
    finding["id"] = "also invalid"

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


def test_native_codex_no_finding_result_is_sha_bound_pass() -> None:
    result = evaluate_fixture(native_evidence())

    assert result is not None
    assert result.url == NO_FINDINGS_URL
    assert result.trigger_url == TRIGGER_URL
    assert result.ready_url == READY_URL
    assert result.result["verdict"] == "PASS"
    assert result.result["reviewed_sha"] == HEAD_SHA
    assert result.result["base_sha"] == BASE_SHA
    assert result.result["findings"] == []


def test_native_codex_pass_requires_reviewer_thumbs_up() -> None:
    evidence = native_evidence()
    evidence["reactions"] = []

    assert evaluate_fixture(evidence) is None


def test_native_review_rejects_ready_marker_unknown_field() -> None:
    evidence = native_evidence()
    ready = evidence["ready"]
    assert isinstance(ready, MarkerEvidence)
    evidence["ready"] = MarkerEvidence(
        payload={**ready.payload, "untrusted": True},
        url=ready.url,
        author=ready.author,
        body=ready.body,
    )

    with pytest.raises(UntrustedEvidenceError, match="unknown fields"):
        evaluate_fixture(evidence)


def test_native_codex_pass_rejects_stale_commit_prefix() -> None:
    evidence = native_evidence()
    comments = evidence["comments"]
    assert isinstance(comments, list)
    comments[-1]["body"] = (
        "Codex Review: Didn't find any major issues.\n\n"
        f"**Reviewed commit:** `{'c' * 10}`"
    )

    with pytest.raises(UntrustedEvidenceError, match="stale commit"):
        evaluate_fixture(evidence)


def test_native_codex_pass_rejects_head_change_during_review() -> None:
    evidence = native_evidence()
    evidence["timeline"] = [
        {"event": "synchronize", "created_at": "2026-08-30T00:01:30Z"}
    ]

    with pytest.raises(UntrustedEvidenceError, match="head changed"):
        evaluate_fixture(evidence)


def test_native_codex_p1_becomes_changes_requested() -> None:
    evidence = native_evidence()
    comments = evidence["comments"]
    assert isinstance(comments, list)
    comments.pop()
    evidence["reactions"] = []
    evidence["reviews"] = [
        {
            "id": 77,
            "html_url": REVIEW_URL,
            "user": {"login": REVIEWER_LOGIN},
            "commit_id": HEAD_SHA,
            "state": "COMMENTED",
            "submitted_at": "2026-08-30T00:02:00Z",
        }
    ]
    finding = {
        "id": 88,
        "html_url": f"{REVIEW_URL}#discussion-88",
        "user": {"login": REVIEWER_LOGIN},
        "commit_id": HEAD_SHA,
        "pull_request_review_id": 77,
        "created_at": "2026-08-30T00:02:00Z",
        "path": "docs/review/phase-0a-fix-report.md",
        "line": 10,
        "body": "![P1 Badge](badge) H-07 evidence is stale",
    }
    evidence["review_comments"] = [finding]

    result = evaluate_fixture(evidence)

    assert result is not None
    assert result.url == REVIEW_URL
    assert result.commit_id == HEAD_SHA
    assert result.result["verdict"] == "CHANGES_REQUESTED"
    assert result.result["findings"] == [
        {
            "id": native_finding_key(finding),
            "severity": "HIGH",
            "requirement_id": "H-07",
            "evidence": "docs/review/phase-0a-fix-report.md:10; Codex review comment 88",
            "required_fix": (
                "Resolve the referenced Codex P0/P1 finding without weakening controls."
            ),
            "retest": ["bash scripts/ci/run_phase_gate.sh phase-0a"],
        }
    ]


def test_native_codex_formal_review_without_retained_finding_fails_closed() -> None:
    evidence = native_evidence()
    evidence["reviews"] = [
        {
            "id": 77,
            "html_url": REVIEW_URL,
            "user": {"login": REVIEWER_LOGIN},
            "commit_id": HEAD_SHA,
            "state": "COMMENTED",
            "submitted_at": "2026-08-30T00:02:00Z",
        }
    ]

    with pytest.raises(UntrustedEvidenceError, match="missing retained"):
        evaluate_fixture(evidence)


def test_native_finding_key_is_stable_when_only_line_number_changes() -> None:
    finding = {
        "path": "src/redteam_agent/policy/engine.py",
        "line": 10,
        "body": "![P0 Badge](badge) caller can bypass policy",
    }
    changed_line = {**finding, "line": 99}

    assert native_finding_key(finding) == native_finding_key(changed_line)
