from __future__ import annotations

import json
from pathlib import Path

import pytest

from automation.run_phase_loop import (
    PHASES,
    GitHubClient,
    MarkerEvidence,
    PhaseLoop,
    PrerequisiteError,
    PullRequestState,
    ReviewEvidence,
    UntrustedEvidenceError,
    canonical_digest,
    codex_implementation_blocker,
    evaluate_native_review,
    marker_payloads,
    native_finding_key,
    select_evidence_action,
    select_finding_key,
    strict_json_loads,
    validate_base_refresh,
    validate_implementation_request,
    validate_review_result,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40
DEFAULT_BRANCH_SHA = "d" * 40
REFRESHED_HEAD_SHA = "e" * 40
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


def phase_state(*, phase: str = "phase-0a") -> PullRequestState:
    return PullRequestState(
        number=3,
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        base_ref="main",
        phase=phase,
        labels=frozenset({"ai-loop", "ai-needs-implementation", phase}),
        state="open",
        head_repository="example/repo",
    )


def base_refresh_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "action": "REFRESH_BASE",
        "from_phase": "phase-0b",
        "revalidate_phase": "phase-0a",
        "head_sha": HEAD_SHA,
        "target_base_sha": BASE_SHA,
        "prior_pass_reference": "https://github.com/example/repo/pull/3#issuecomment-pass",
    }


def test_base_refresh_is_bound_to_adjacent_phase_head_and_default_branch() -> None:
    validate_base_refresh(
        base_refresh_payload(), state=phase_state(), target_base_sha=BASE_SHA
    )


class _AncestorGitHub:
    def __init__(self, ancestors: set[tuple[str, str]]) -> None:
        self.ancestors = ancestors

    def is_ancestor(self, ancestor_sha: str, descendant_sha: str) -> bool:
        return (ancestor_sha, descendant_sha) in self.ancestors


def refreshed_phase_state() -> PullRequestState:
    return PullRequestState(
        number=3,
        head_sha=REFRESHED_HEAD_SHA,
        base_sha=BASE_SHA,
        base_ref="main",
        phase="phase-0a",
        labels=frozenset({"ai-loop", "ai-ready-for-review", "phase-0a"}),
        state="open",
        head_repository="example/repo",
    )


def base_refresh_record() -> MarkerEvidence:
    payload = base_refresh_payload()
    payload["target_base_sha"] = DEFAULT_BRANCH_SHA
    return MarkerEvidence(
        payload,
        "https://github.com/example/repo/pull/3#issuecomment-refresh",
        "github-actions[bot]",
        "",
    )


def test_phase_zero_a_review_uses_trusted_refreshed_base_not_pr_base_sha() -> None:
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = _AncestorGitHub(  # type: ignore[assignment]
        {
            (HEAD_SHA, REFRESHED_HEAD_SHA),
            (DEFAULT_BRANCH_SHA, REFRESHED_HEAD_SHA),
        }
    )

    assert (
        loop.expected_base_sha(
            refreshed_phase_state(), [], [base_refresh_record()], DEFAULT_BRANCH_SHA
        )
        == DEFAULT_BRANCH_SHA
    )


def test_phase_zero_a_review_rejects_unrelated_refreshed_head() -> None:
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = _AncestorGitHub(  # type: ignore[assignment]
        {(HEAD_SHA, REFRESHED_HEAD_SHA)}
    )

    with pytest.raises(UntrustedEvidenceError, match="not descended"):
        loop.expected_base_sha(
            refreshed_phase_state(), [], [base_refresh_record()], DEFAULT_BRANCH_SHA
        )


def test_phase_zero_a_review_rejects_refresh_when_default_branch_advanced() -> None:
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = _AncestorGitHub(  # type: ignore[assignment]
        {
            (HEAD_SHA, REFRESHED_HEAD_SHA),
            (DEFAULT_BRANCH_SHA, REFRESHED_HEAD_SHA),
        }
    )

    with pytest.raises(UntrustedEvidenceError, match="stale for the current default branch"):
        loop.expected_base_sha(
            refreshed_phase_state(), [], [base_refresh_record()], "f" * 40
        )


def test_initial_phase_zero_a_review_keeps_original_pr_base_sha() -> None:
    loop = PhaseLoop.__new__(PhaseLoop)

    assert loop.expected_base_sha(phase_state(), [], [], DEFAULT_BRANCH_SHA) == BASE_SHA


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("from_phase", "phase-0c", "exactly one phase"),
        ("head_sha", "c" * 40, "stale for the current PR head"),
        ("target_base_sha", "d" * 40, "stale for the default branch"),
    ],
)
def test_base_refresh_rejects_non_adjacent_or_stale_evidence(
    field: str, value: str, message: str
) -> None:
    payload = base_refresh_payload()
    payload[field] = value

    with pytest.raises(UntrustedEvidenceError, match=message):
        validate_base_refresh(payload, state=phase_state(), target_base_sha=BASE_SHA)


def test_stale_base_refresh_is_reauthorized_for_new_default_head() -> None:
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.dispatched_base_refreshes = set()
    loop.started_base_updates = set()
    loop.dry_run = True
    loop.log = lambda _message: None  # type: ignore[method-assign]
    stale_payload = base_refresh_payload()
    stale_payload["target_base_sha"] = "c" * 40
    stale_record = MarkerEvidence(
        stale_payload,
        "https://github.com/example/repo/pull/3#issuecomment-refresh",
        "github-actions[bot]",
        "",
    )

    assert loop.perform_pending_base_refresh(
        phase_state(), [stale_record], BASE_SHA
    ) is True
    assert loop.dispatched_base_refreshes == {f"phase-0b:{HEAD_SHA}:{BASE_SHA}"}
    assert loop.started_base_updates == set()


def test_sha_bound_codex_implementation_blocker_is_detected() -> None:
    request = implementation_request()
    digest = canonical_digest(request)
    trigger_body = marker(
        "redteam-local-codex-trigger",
        {
            "schema_version": "1.0",
            "kind": "implementation",
            "phase": "phase-0a",
            "head_sha": HEAD_SHA,
            "source_digest": digest,
        },
    )
    comments = [
        {
            "user": {"login": ACTOR_LOGIN},
            "created_at": "2026-08-30T00:00:00Z",
            "body": trigger_body,
        },
        {
            "user": {"login": REVIEWER_LOGIN},
            "created_at": "2026-08-30T00:01:00Z",
            "html_url": "https://github.com/example/repo/pull/3#issuecomment-blocked",
            "body": f"## BLOCKED\n\nPhase: phase-0a\nInput SHA: {HEAD_SHA}",
        },
    ]

    assert codex_implementation_blocker(
        comments=comments,
        actor_login=ACTOR_LOGIN,
        reviewer_login=REVIEWER_LOGIN,
        phase="phase-0a",
        head_sha=HEAD_SHA,
        source_digest=digest,
    ) == "https://github.com/example/repo/pull/3#issuecomment-blocked"


def test_codex_blocker_for_another_sha_is_ignored() -> None:
    request = implementation_request()
    digest = canonical_digest(request)
    comments = [
        {
            "user": {"login": ACTOR_LOGIN},
            "created_at": "2026-08-30T00:00:00Z",
            "body": marker(
                "redteam-local-codex-trigger",
                {
                    "schema_version": "1.0",
                    "kind": "implementation",
                    "phase": "phase-0a",
                    "head_sha": HEAD_SHA,
                    "source_digest": digest,
                },
            ),
        },
        {
            "user": {"login": REVIEWER_LOGIN},
            "created_at": "2026-08-30T00:01:00Z",
            "html_url": "https://github.com/example/repo/pull/3#issuecomment-stale",
            "body": f"## BLOCKED\n\nPhase: phase-0a\nInput SHA: {'c' * 40}",
        },
    ]

    assert codex_implementation_blocker(
        comments=comments,
        actor_login=ACTOR_LOGIN,
        reviewer_login=REVIEWER_LOGIN,
        phase="phase-0a",
        head_sha=HEAD_SHA,
        source_digest=digest,
    ) is None


class _CompareGitHub:
    def __init__(self, ahead_by: int) -> None:
        self.ahead_by = ahead_by

    def compare(self, base_sha: str, head_sha: str) -> dict[str, object]:
        assert (base_sha, head_sha) == (HEAD_SHA, DEFAULT_BRANCH_SHA)
        return {"ahead_by": self.ahead_by}


def test_base_refresh_candidate_requires_prior_pass_on_current_head() -> None:
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = _CompareGitHub(ahead_by=1)  # type: ignore[assignment]
    loop.implementation_schema = load_schema("implementation-request.schema.json")
    loop.phase_prompts = {phase: f"prompts/phases/{phase}.md" for phase in PHASES}
    loop.phase_prompts["phase-0b"] = "prompts/phases/phase-0b.md"
    request_payload = {
        "schema_version": "1.0",
        "action": "IMPLEMENT_PHASE",
        "trigger": "PHASE_START",
        "phase": "phase-0b",
        "head_sha": HEAD_SHA,
        "phase_prompt": "prompts/phases/phase-0b.md",
    }
    request = MarkerEvidence(request_payload, "request-url", "github-actions[bot]", "")
    prior_pass = MarkerEvidence(
        {"phase": "phase-0a", "verdict": "PASS", "reviewed_sha": HEAD_SHA},
        "pass-url",
        "github-actions[bot]",
        "",
    )

    assert loop.base_refresh_candidate(
        phase_state(phase="phase-0b"),
        [request],
        [prior_pass],
        DEFAULT_BRANCH_SHA,
    ) == prior_pass


def test_base_refresh_candidate_is_absent_when_main_has_not_advanced() -> None:
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = _CompareGitHub(ahead_by=0)  # type: ignore[assignment]
    loop.implementation_schema = load_schema("implementation-request.schema.json")
    loop.phase_prompts = {"phase-0b": "prompts/phases/phase-0b.md"}
    request = MarkerEvidence(
        {
            "schema_version": "1.0",
            "action": "IMPLEMENT_PHASE",
            "trigger": "PHASE_START",
            "phase": "phase-0b",
            "head_sha": HEAD_SHA,
            "phase_prompt": "prompts/phases/phase-0b.md",
        },
        "request-url",
        "github-actions[bot]",
        "",
    )
    prior_pass = MarkerEvidence(
        {"phase": "phase-0a", "verdict": "PASS", "reviewed_sha": HEAD_SHA},
        "pass-url",
        "github-actions[bot]",
        "",
    )

    assert loop.base_refresh_candidate(
        phase_state(phase="phase-0b"),
        [request],
        [prior_pass],
        DEFAULT_BRANCH_SHA,
    ) is None


class _DefaultBranchGitHub:
    def default_branch_sha(self, branch: str) -> str:
        assert branch == "main"
        return DEFAULT_BRANCH_SHA


def test_runner_stops_if_default_branch_changes_after_startup() -> None:
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = _DefaultBranchGitHub()  # type: ignore[assignment]
    loop.default_branch = "main"
    loop.trusted_default_branch_sha = BASE_SHA

    with pytest.raises(PrerequisiteError, match="changed after startup"):
        loop.current_default_branch_sha()


class _RecordingCommand:
    def __init__(self) -> None:
        self.arguments: list[str] = []

    def run(self, arguments: list[str]) -> str:
        self.arguments = arguments
        return '{"message":"Updating pull request branch."}'


class _ComparisonGitHub:
    is_ancestor = GitHubClient.is_ancestor

    def __init__(self, comparison: dict[str, object]) -> None:
        self.comparison = comparison

    def compare(self, base_sha: str, head_sha: str) -> dict[str, object]:
        assert (base_sha, head_sha) == (HEAD_SHA, REFRESHED_HEAD_SHA)
        return self.comparison


@pytest.mark.parametrize(
    ("comparison", "expected"),
    [
        (
            {
                "merge_base_commit": {"sha": HEAD_SHA},
                "behind_by": 0,
                "status": "ahead",
            },
            True,
        ),
        (
            {
                "merge_base_commit": {"sha": HEAD_SHA},
                "behind_by": 0,
                "status": "identical",
            },
            True,
        ),
        (
            {
                "merge_base_commit": {"sha": HEAD_SHA},
                "behind_by": 1,
                "status": "diverged",
            },
            False,
        ),
        (
            {
                "merge_base_commit": {"sha": BASE_SHA},
                "behind_by": 0,
                "status": "ahead",
            },
            False,
        ),
    ],
)
def test_ancestor_check_requires_exact_merge_base_and_forward_history(
    comparison: dict[str, object], expected: bool
) -> None:
    github = _ComparisonGitHub(comparison)

    assert github.is_ancestor(HEAD_SHA, REFRESHED_HEAD_SHA) is expected


def test_branch_update_uses_expected_head_and_never_final_merge_endpoint() -> None:
    client = GitHubClient.__new__(GitHubClient)
    client.repository = "example/repo"
    command = _RecordingCommand()
    client.command = command  # type: ignore[assignment]

    client.update_pull_request_branch(3, HEAD_SHA)

    assert command.arguments == [
        "api",
        "--method",
        "PUT",
        "repos/example/repo/pulls/3/update-branch",
        "--raw-field",
        f"expected_head_sha={HEAD_SHA}",
    ]
    assert "/merge" not in " ".join(command.arguments)
