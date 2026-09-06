from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from automation.local_execution import LocalExecution
from automation.run_phase_loop import (
    BASE_REFRESH_CHECKPOINT_STATUS_DESCRIPTION,
    BASE_REFRESH_CHECKPOINT_STATUS_PREFIX,
    BASE_REFRESH_STATUS_DESCRIPTION,
    PHASES,
    FinalMergeReconciliationRequiredError,
    FinalMergeRejectedError,
    GitHubClient,
    LoopBlockedError,
    MarkerEvidence,
    PhaseLoop,
    PrerequisiteError,
    PullRequestState,
    ReviewEvidence,
    UntrustedEvidenceError,
    base_refresh_checkpoint_from_statuses,
    base_refresh_checkpoint_payload,
    base_refresh_evidence_from_statuses,
    canonical_digest,
    codex_implementation_blocker,
    current_phase_from_labels,
    evaluate_native_review,
    invariant_audit_from_ready,
    marker_payloads,
    native_finding_key,
    review_trigger_source,
    select_evidence_action,
    select_finding_key,
    strict_json_loads,
    validate_base_refresh,
    validate_design_approval,
    validate_final_merge_attempt_payload,
    validate_final_merge_phase_chain,
    validate_final_phase_status,
    validate_implementation_request,
    validate_review_result,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40
DEFAULT_BRANCH_SHA = "d" * 40
REFRESHED_HEAD_SHA = "e" * 40
SECOND_DEFAULT_BRANCH_SHA = "f" * 40
SECOND_REFRESHED_HEAD_SHA = "7" * 40
IMPLEMENTATION_OUTPUT_HEAD_SHA = "8" * 40
ACTOR_LOGIN = "operator"
REVIEWER_LOGIN = "chatgpt-codex-connector[bot]"
READY_URL = "https://github.com/example/repo/pull/1#issuecomment-ready"
TRIGGER_URL = "https://github.com/example/repo/pull/1#issuecomment-trigger"
NO_FINDINGS_URL = "https://github.com/example/repo/pull/1#issuecomment-no-findings"
REVIEW_URL = "https://github.com/example/repo/pull/1#pullrequestreview-77"
PHASE_RECORD_URL = "https://github.com/example/repo/pull/3#issuecomment-record"
PHASE_ONE_RECORD_URL = "https://github.com/example/repo/pull/3#issuecomment-phase-one"
PHASE_ZERO_B_RECORD_URL = "https://github.com/example/repo/pull/3#issuecomment-phase-zero-b"
PHASE_ZERO_C_RECORD_URL = "https://github.com/example/repo/pull/3#issuecomment-phase-zero-c"
PULL_REQUEST_PREFIX = "https://github.com/example/repo/pull/3"


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
                "invariant_family": "authorization-lifecycle",
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


def chained_phase_passes() -> list[MarkerEvidence]:
    records: list[MarkerEvidence] = []
    base_sha = "0" * 40
    for index, phase in enumerate(PHASES, start=1):
        reviewed_sha = f"{index:x}" * 40
        url = f"{PULL_REQUEST_PREFIX}#issuecomment-{index}"
        payload: dict[str, object] = {
            "schema_version": "1.0",
            "phase": phase,
            "reviewed_sha": reviewed_sha,
            "base_sha": base_sha,
            "verdict": "PASS",
            "summary": f"{phase} passed independent review",
            "evidence_format": "codex-native-v1",
            "review_reference": f"{PULL_REQUEST_PREFIX}#issuecomment-review-{index}",
            "ready_reference": f"{PULL_REQUEST_PREFIX}#issuecomment-ready-{index}",
            "review_trigger_reference": f"{PULL_REQUEST_PREFIX}#issuecomment-trigger-{index}",
            "reviewer_login": REVIEWER_LOGIN,
            "recorded_by": ACTOR_LOGIN,
            "finding_key": None,
            "required_checks": [
                {"name": "tests (3.12)", "status": "PASS"},
                {"name": "tests (3.14)", "status": "PASS"},
                {"name": "quality", "status": "PASS"},
                {"name": "governance-integrity", "status": "PASS"},
            ],
            "loop_state": "PASS",
        }
        records.append(MarkerEvidence(payload, url, "github-actions[bot]", ""))
        base_sha = reviewed_sha
    return records


def final_phase_status(record: MarkerEvidence) -> dict[str, object]:
    return {
        "context": "redteam/phase-review",
        "creator": {"login": "github-actions[bot]"},
        "sha": record.payload["reviewed_sha"],
        "state": "success",
        "description": "phase-5: independent review PASS",
        "target_url": record.url,
    }


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


def test_final_merge_requires_one_exact_sha_bound_phase_chain() -> None:
    records = chained_phase_passes()

    result = validate_final_merge_phase_chain(
        records,
        head_sha="8" * 40,
        reviewer_login=REVIEWER_LOGIN,
        approver_login=ACTOR_LOGIN,
        pull_request_prefix=PULL_REQUEST_PREFIX,
    )

    assert result.payload["phase"] == "phase-5"
    assert result.payload["reviewed_sha"] == "8" * 40


def test_final_merge_rejects_unknown_phase_record_field() -> None:
    records = chained_phase_passes()
    records[-1].payload["unexpected"] = True

    with pytest.raises(UntrustedEvidenceError, match="missing or unknown fields"):
        validate_final_merge_phase_chain(
            records,
            head_sha="8" * 40,
            reviewer_login=REVIEWER_LOGIN,
            approver_login=ACTOR_LOGIN,
            pull_request_prefix=PULL_REQUEST_PREFIX,
        )


def test_final_merge_rejects_a_different_pr_with_a_shared_number_prefix() -> None:
    records = chained_phase_passes()
    records[-1].payload["review_reference"] = (
        "https://github.com/example/repo/pull/30#issuecomment-review"
    )

    with pytest.raises(UntrustedEvidenceError, match="invalid review reference"):
        validate_final_merge_phase_chain(
            records,
            head_sha="8" * 40,
            reviewer_login=REVIEWER_LOGIN,
            approver_login=ACTOR_LOGIN,
            pull_request_prefix=PULL_REQUEST_PREFIX,
        )


def test_final_merge_rejects_a_broken_or_ambiguous_phase_chain() -> None:
    records = chained_phase_passes()
    records[-1].payload["base_sha"] = "f" * 40

    with pytest.raises(UntrustedEvidenceError, match="exactly one chained PASS for phase-4"):
        validate_final_merge_phase_chain(
            records,
            head_sha="8" * 40,
            reviewer_login=REVIEWER_LOGIN,
            approver_login=ACTOR_LOGIN,
            pull_request_prefix=PULL_REQUEST_PREFIX,
        )


def test_final_merge_requires_latest_trusted_phase_status() -> None:
    record = chained_phase_passes()[-1]

    validate_final_phase_status(
        [final_phase_status(record)],
        head_sha="8" * 40,
        final_record_url=record.url,
        context="redteam/phase-review",
    )

    untrusted = final_phase_status(record)
    untrusted["creator"] = {"login": "attacker"}
    with pytest.raises(UntrustedEvidenceError, match="untrusted, stale, or non-passing"):
        validate_final_phase_status(
            [untrusted],
            head_sha="8" * 40,
            final_record_url=record.url,
            context="redteam/phase-review",
        )


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


def test_design_resume_request_requires_exact_approval_reference() -> None:
    payload = implementation_request()
    payload.update(
        {
            "action": "IMPLEMENT_PHASE",
            "trigger": "RESUME_AFTER_DESIGN_APPROVAL",
            "phase": "phase-0c",
            "phase_prompt": "prompts/phases/phase-0c.md",
        }
    )
    with pytest.raises(UntrustedEvidenceError, match="schema failure"):
        validate_implementation_request(
            payload,
            schema=load_schema("implementation-request.schema.json"),
            phase="phase-0c",
            head_sha=HEAD_SHA,
            phase_prompt="prompts/phases/phase-0c.md",
        )

    payload["design_approval_reference"] = (
        f"{PULL_REQUEST_PREFIX}#issuecomment-99"
    )
    validate_implementation_request(
        payload,
        schema=load_schema("implementation-request.schema.json"),
        phase="phase-0c",
        head_sha=HEAD_SHA,
        phase_prompt="prompts/phases/phase-0c.md",
    )


def test_design_approval_is_closed_and_fully_bound() -> None:
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "phase": "phase-0c",
        "head_sha": HEAD_SHA,
        "blocked_gate_reference": f"{PULL_REQUEST_PREFIX}#issuecomment-88",
        "design_commit_sha": "c" * 40,
        "design_reference": "https://github.com/example/repo/pull/28",
        "policy_digest": "f" * 64,
        "approved_by": ACTOR_LOGIN,
    }
    validate_design_approval(
        payload,
        schema=load_schema("design-approval.schema.json"),
        phase="phase-0c",
        head_sha=HEAD_SHA,
        blocked_gate_reference=f"{PULL_REQUEST_PREFIX}#issuecomment-88",
        policy_digest="f" * 64,
        approver_login=ACTOR_LOGIN,
        pull_request_prefix=PULL_REQUEST_PREFIX,
    )

    payload["secret_override"] = True
    with pytest.raises(UntrustedEvidenceError, match="schema failure"):
        validate_design_approval(
            payload,
            schema=load_schema("design-approval.schema.json"),
            phase="phase-0c",
            head_sha=HEAD_SHA,
            blocked_gate_reference=f"{PULL_REQUEST_PREFIX}#issuecomment-88",
            policy_digest="f" * 64,
            approver_login=ACTOR_LOGIN,
            pull_request_prefix=PULL_REQUEST_PREFIX,
        )


def test_fix_request_requires_total_finding_count() -> None:
    payload = {
        **implementation_request(),
        "action": "FIX_REVIEW_FINDINGS",
        "trigger": "REVIEW_FINDINGS",
        "review": {
            "reviewed_sha": HEAD_SHA,
            "review_reference": REVIEW_URL,
            "finding_key": "CODEX-P1-ALL-FINDINGS",
            "finding_count": 2,
            "findings": [
                {
                    "finding_key": "CODEX-P1-ALL-FINDINGS",
                    "finding_reference": f"{REVIEW_URL}#discussion-1",
                },
                {
                    "finding_key": "CODEX-P0-SECOND-FINDING",
                    "finding_reference": f"{REVIEW_URL}#discussion-2",
                },
            ],
            "summary": "Codex reported 2 P0/P1 findings.",
        },
    }

    validate_implementation_request(
        payload,
        schema=load_schema("implementation-request.schema.json"),
        phase="phase-0a",
        head_sha=HEAD_SHA,
        phase_prompt="prompts/phases/phase-0a-security-fix.md",
    )
    count_mismatch = json.loads(json.dumps(payload))
    count_mismatch["review"]["finding_count"] = 1
    with pytest.raises(UntrustedEvidenceError, match="finding count"):
        validate_implementation_request(
            count_mismatch,
            schema=load_schema("implementation-request.schema.json"),
            phase="phase-0a",
            head_sha=HEAD_SHA,
            phase_prompt="prompts/phases/phase-0a-security-fix.md",
        )
    del payload["review"]["finding_count"]  # type: ignore[index]
    with pytest.raises(UntrustedEvidenceError, match="schema failure"):
        validate_implementation_request(
            payload,
            schema=load_schema("implementation-request.schema.json"),
            phase="phase-0a",
            head_sha=HEAD_SHA,
            phase_prompt="prompts/phases/phase-0a-security-fix.md",
        )


def test_audited_fix_request_requires_family_for_every_finding() -> None:
    payload = {
        **implementation_request(),
        "action": "FIX_REVIEW_FINDINGS",
        "trigger": "REVIEW_FINDINGS",
        "invariant_audit": {"policy_version": "1.0", "required": True},
        "review": {
            "reviewed_sha": HEAD_SHA,
            "review_reference": REVIEW_URL,
            "finding_key": "CODEX-P1-ALL-FINDINGS",
            "finding_count": 1,
            "findings": [
                {
                    "finding_key": "CODEX-P1-ALL-FINDINGS",
                    "finding_reference": f"{REVIEW_URL}#discussion-1",
                }
            ],
            "summary": "Codex reported one P1 finding.",
        },
    }

    with pytest.raises(UntrustedEvidenceError, match="classify every finding"):
        validate_implementation_request(
            payload,
            schema=load_schema("implementation-request.schema.json"),
            phase="phase-0a",
            head_sha=HEAD_SHA,
            phase_prompt="prompts/phases/phase-0a-security-fix.md",
        )

    payload["review"]["findings"][0]["invariant_family"] = "authorization-lifecycle"  # type: ignore[index]
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
        )
        == "implementation"
    )


def test_missing_current_head_evidence_waits() -> None:
    assert select_evidence_action(request_exists=False, ready_exists=False) == "wait"


def test_current_head_request_is_authority_when_projection_label_is_delayed() -> None:
    assert select_evidence_action(request_exists=True, ready_exists=False) == "implementation"


def test_ready_evidence_is_authority_when_no_request_exists() -> None:
    assert select_evidence_action(request_exists=False, ready_exists=True) == "review"


@pytest.mark.parametrize("phase", PHASES)
def test_single_phase_is_accepted_with_or_without_transition_marker(phase: str) -> None:
    assert current_phase_from_labels(frozenset({phase})) == phase
    assert current_phase_from_labels(frozenset({phase, "ai-review-passed"})) == phase


@pytest.mark.parametrize(
    ("current_phase", "next_phase"),
    tuple(zip(PHASES[:-1], PHASES[1:], strict=True)),
)
def test_marked_adjacent_dual_phase_is_treated_as_in_progress(
    current_phase: str, next_phase: str
) -> None:
    labels = frozenset({current_phase, next_phase, "ai-review-passed"})

    assert current_phase_from_labels(labels) == next_phase


@pytest.mark.parametrize(
    "labels",
    [
        frozenset(),
        frozenset({"phase-0a", "phase-0b"}),
        frozenset({"phase-0a", "phase-1", "ai-review-passed"}),
        frozenset({"phase-0a", "phase-0b", "phase-0c", "ai-review-passed"}),
    ],
)
def test_unmarked_or_non_adjacent_phase_ambiguity_fails_closed(
    labels: frozenset[str],
) -> None:
    with pytest.raises(UntrustedEvidenceError):
        current_phase_from_labels(labels)


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


def test_review_trigger_source_binds_invariant_audit_digest() -> None:
    ready_payload = {"schema_version": "1.0", "phase": "phase-0a", "head_sha": HEAD_SHA}
    audit_payload = {
        "schema_version": "1.0",
        "phase": "phase-0a",
        "head_sha": HEAD_SHA,
        "audit_path": "docs/review/phase-0a-invariant-audit.json",
        "audit_digest": "c" * 64,
        "request_reference": "https://github.com/example/repo/pull/1#issuecomment-request",
    }
    ready = MarkerEvidence(
        payload=ready_payload,
        url=READY_URL,
        author="github-actions[bot]",
        body=(
            f"{marker('redteam-invariant-audit', audit_payload)}\n\n"
            f"{marker('redteam-ready-for-review', ready_payload)}"
        ),
    )

    assert invariant_audit_from_ready(ready, phase="phase-0a", head_sha=HEAD_SHA) == audit_payload
    source = review_trigger_source(
        ready=ready, phase="phase-0a", head_sha=HEAD_SHA, base_sha=BASE_SHA
    )
    assert source["audit_digest"] == "c" * 64
    assert source["request_reference"] == audit_payload["request_reference"]


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


def test_native_codex_pass_ignores_stale_commit_before_trusted_trigger() -> None:
    evidence = native_evidence()
    comments = evidence["comments"]
    assert isinstance(comments, list)
    comments.insert(
        1,
        {
            "id": 5,
            "html_url": "https://github.com/example/repo/pull/1#issuecomment-old-pass",
            "user": {"login": REVIEWER_LOGIN},
            "created_at": "2026-08-30T00:00:30Z",
            "body": (
                "Codex Review: Didn't find any major issues.\n\n"
                f"**Reviewed commit:** `{'c' * 10}`"
            ),
        },
    )

    result = evaluate_fixture(evidence)

    assert result is not None
    assert result.result["reviewed_sha"] == HEAD_SHA
    assert result.url == NO_FINDINGS_URL


def test_native_codex_pass_ignores_remapped_finding_before_trusted_trigger() -> None:
    evidence = native_evidence()
    review_comments = evidence["review_comments"]
    assert isinstance(review_comments, list)
    review_comments.append(
        {
            "id": 6,
            "html_url": f"{REVIEW_URL}#discussion-old",
            "user": {"login": REVIEWER_LOGIN},
            "commit_id": HEAD_SHA,
            "original_commit_id": "c" * 40,
            "pull_request_review_id": 66,
            "created_at": "2026-08-30T00:00:30Z",
            "path": "src/redteam_agent/executor/service.py",
            "line": 10,
            "body": "![P1 Badge](badge) historical finding remapped to current head",
        }
    )

    result = evaluate_fixture(evidence)

    assert result is not None
    assert result.result["verdict"] == "PASS"
    assert result.url == NO_FINDINGS_URL


def test_native_codex_pass_ignores_malformed_finding_before_trusted_trigger() -> None:
    evidence = native_evidence()
    review_comments = evidence["review_comments"]
    assert isinstance(review_comments, list)
    review_comments.append(
        {
            "id": 7,
            "html_url": f"{REVIEW_URL}#discussion-old-malformed",
            "user": {"login": REVIEWER_LOGIN},
            "commit_id": HEAD_SHA,
            "pull_request_review_id": 67,
            "created_at": "2026-08-30T00:00:30Z",
            "path": "src/redteam_agent/executor/service.py",
            "line": 11,
            "body": "![P0 Badge](badge) ![P1 Badge](badge) ambiguous historical finding",
        }
    )

    result = evaluate_fixture(evidence)

    assert result is not None
    assert result.result["verdict"] == "PASS"


def test_native_codex_finding_after_trigger_requires_trusted_review() -> None:
    evidence = native_evidence()
    review_comments = evidence["review_comments"]
    assert isinstance(review_comments, list)
    review_comments.append(
        {
            "id": 8,
            "html_url": f"{REVIEW_URL}#discussion-unbound",
            "user": {"login": REVIEWER_LOGIN},
            "commit_id": HEAD_SHA,
            "pull_request_review_id": 68,
            "created_at": "2026-08-30T00:01:30Z",
            "path": "src/redteam_agent/executor/service.py",
            "line": 12,
            "body": "![P1 Badge](badge) unbound post-trigger finding",
        }
    )

    with pytest.raises(UntrustedEvidenceError, match="not bound to a trusted"):
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
        "body": (
            "![P1 Badge](badge) H-07 evidence is stale\n\n"
            "Invariant family: `acceptance-compatibility`"
        ),
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
            "invariant_family": "acceptance-compatibility",
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


def test_one_native_review_aggregates_every_p0_p1_finding() -> None:
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
    evidence["review_comments"] = [
        {
            "id": 88,
            "html_url": f"{REVIEW_URL}#discussion-88",
            "user": {"login": REVIEWER_LOGIN},
            "commit_id": HEAD_SHA,
            "pull_request_review_id": 77,
            "created_at": "2026-08-30T00:02:00Z",
            "path": "src/redteam_agent/policy/engine.py",
            "line": 10,
            "body": (
                "![P0 Badge](badge) H-01 authorization bypass\n\n"
                "Invariant family: `authorization-lifecycle`"
            ),
        },
        {
            "id": 89,
            "html_url": f"{REVIEW_URL}#discussion-89",
            "user": {"login": REVIEWER_LOGIN},
            "commit_id": HEAD_SHA,
            "pull_request_review_id": 77,
            "created_at": "2026-08-30T00:02:00Z",
            "path": "src/redteam_agent/output/pipeline.py",
            "line": 20,
            "body": (
                "![P1 Badge](badge) H-02 raw output reaches the planner\n\n"
                "Invariant family: `secret-plaintext-boundary`"
            ),
        },
    ]

    result = evaluate_fixture(evidence)

    assert result is not None
    assert result.result["verdict"] == "CHANGES_REQUESTED"
    assert [item["severity"] for item in result.result["findings"]] == [
        "BLOCKER",
        "HIGH",
    ]


def test_exhaustive_findings_split_across_formal_reviews_fail_closed() -> None:
    evidence = native_evidence()
    comments = evidence["comments"]
    assert isinstance(comments, list)
    comments.pop()
    evidence["reactions"] = []
    evidence["reviews"] = [
        {
            "id": review_id,
            "html_url": f"{REVIEW_URL}-{review_id}",
            "user": {"login": REVIEWER_LOGIN},
            "commit_id": HEAD_SHA,
            "state": "COMMENTED",
            "submitted_at": "2026-08-30T00:02:00Z",
        }
        for review_id in (77, 78)
    ]
    evidence["review_comments"] = [
        {
            "id": 100 + review_id,
            "html_url": f"{REVIEW_URL}-{review_id}#discussion",
            "user": {"login": REVIEWER_LOGIN},
            "commit_id": HEAD_SHA,
            "pull_request_review_id": review_id,
            "created_at": "2026-08-30T00:02:00Z",
            "path": f"src/redteam_agent/review_{review_id}.py",
            "line": 10,
            "body": (
                f"![P1 Badge](badge) H-01 finding from review {review_id}\n\n"
                "Invariant family: `authorization-lifecycle`"
            ),
        }
        for review_id in (77, 78)
    ]

    with pytest.raises(UntrustedEvidenceError, match="one formal review"):
        evaluate_fixture(evidence)


def test_native_finding_key_is_stable_when_only_line_number_changes() -> None:
    finding = {
        "path": "src/redteam_agent/policy/engine.py",
        "line": 10,
        "body": "![P0 Badge](badge) caller can bypass policy",
    }
    changed_line = {**finding, "line": 99}

    assert native_finding_key(finding) == native_finding_key(changed_line)


def test_current_native_finding_requires_one_invariant_family() -> None:
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
    evidence["review_comments"] = [
        {
            "id": 88,
            "html_url": f"{REVIEW_URL}#discussion-88",
            "user": {"login": REVIEWER_LOGIN},
            "commit_id": HEAD_SHA,
            "pull_request_review_id": 77,
            "created_at": "2026-08-30T00:02:00Z",
            "path": "src/redteam_agent/policy/engine.py",
            "line": 10,
            "body": "![P1 Badge](badge) H-01 authorization bypass",
        }
    ]

    with pytest.raises(UntrustedEvidenceError, match="Invariant family"):
        evaluate_fixture(evidence)


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


class _ReviewPromptGitHub:
    def __init__(self) -> None:
        self.posted: list[str] = []

    def post_comment(self, number: int, body: str) -> dict[str, object]:
        assert number == 3
        self.posted.append(body)
        return {"body": body}


class _LocalExecutorSpy:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def implement(self, *arguments: object) -> None:
        self.calls.append(("implementation", *arguments))

    def review(self, *arguments: object) -> None:
        self.calls.append(("review", *arguments))


def strategy_implementation_loop() -> tuple[PhaseLoop, _ReviewPromptGitHub]:
    github = _ReviewPromptGitHub()
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.actor_login = ACTOR_LOGIN
    loop.reviewer_login = REVIEWER_LOGIN
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    loop.implementation_schema = load_schema("implementation-request.schema.json")
    plan = json.loads((REPO_ROOT / "automation/phase-plan.json").read_text())
    loop.phase_prompts = {item["id"]: item["prompt"] for item in plan["phases"]}
    loop.implementation_audit_policy = plan["invariant_audit"]
    loop.repo_root = REPO_ROOT
    loop._local_executor = _LocalExecutorSpy()
    return loop, github


@pytest.mark.parametrize("phase", PHASES)
def test_each_phase_passes_current_strategy_to_local_implementation(phase: str) -> None:
    loop, github = strategy_implementation_loop()
    payload = {
        **implementation_request(), "phase": phase, "phase_prompt": loop.phase_prompts[phase],
        "invariant_audit": dict(loop.implementation_audit_policy),
    }
    request = MarkerEvidence(payload, PHASE_RECORD_URL, "github-actions[bot]", "")
    loop.request_implementation(phase_state(phase=phase), request, [])
    assert len(loop._local_executor.calls) == 1
    call = loop._local_executor.calls[0]
    assert call == ("implementation", loop, phase_state(phase=phase), request, [])
    assert github.posted == []
    prompt = LocalExecution(REPO_ROOT).implementation_prompt(phase_state(phase=phase), request)
    for expected in (
        HEAD_SHA, PHASE_RECORD_URL, "SystemDesign_AI_Control.md", "SystemDesign Section 38",
        "reuse/replace/new", "storage/recovery", "implementation_strategy", "before/after",
        "Do not infer current authority from archived designs or erase existing state",
        "complete phase gate",
    ):
        assert expected in prompt
    assert "leave changes uncommitted" in prompt
    assert "@codex implement" not in prompt


@pytest.mark.parametrize("audit_policy", [
    None, {"policy_version": "1.0", "required": True},
    {"policy_version": "1.0", "required": True, "implementation_strategy_version": "2.0"},
    {"policy_version": "1.0", "required": True, "implementation_strategy_version": "1.0",
     "skip_strategy": True},
])
def test_implementation_dispatch_rejects_legacy_downgraded_or_unknown_strategy(
    audit_policy: object,
) -> None:
    loop, github = strategy_implementation_loop()
    payload = implementation_request()
    if audit_policy is not None:
        payload["invariant_audit"] = audit_policy
    with pytest.raises(UntrustedEvidenceError):
        loop.request_implementation(
            phase_state(), MarkerEvidence(payload, PHASE_RECORD_URL, "github-actions[bot]", ""), [],
        )
    assert github.posted == []


def test_new_strategy_request_dry_run_does_not_post() -> None:
    loop, github = strategy_implementation_loop()
    loop.dry_run = True
    loop._local_executor = LocalExecution(REPO_ROOT)
    payload = {**implementation_request(), "invariant_audit": loop.implementation_audit_policy}
    loop.request_implementation(
        phase_state(), MarkerEvidence(payload, PHASE_RECORD_URL, "github-actions[bot]", ""), [],
    )
    assert github.posted == []


@pytest.mark.parametrize("phase", PHASES)
def test_every_phase_uses_one_exhaustive_all_findings_review(phase: str) -> None:
    github = _ReviewPromptGitHub()
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.actor_login = ACTOR_LOGIN
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    loop._local_executor = _LocalExecutorSpy()
    ready = MarkerEvidence(
        payload={"schema_version": "1.0", "phase": phase, "head_sha": HEAD_SHA},
        url=READY_URL,
        author="github-actions[bot]",
        body="",
    )

    loop.request_review(phase_state(phase=phase), ready, BASE_SHA, [])

    assert github.posted == []
    assert loop._local_executor.calls == [("review", loop, phase_state(phase=phase),
                                           ready, BASE_SHA, [])]
    prompt = LocalExecution(REPO_ROOT).review_prompt(phase_state(phase=phase), BASE_SHA)
    assert "one exhaustive independent review" in prompt
    assert "applies identically to every Phase" in prompt
    assert "Retain every consequential finding in this single structured review" in prompt
    assert "`BLOCKER`/`HIGH` severity" in prompt
    assert "invariant_family" in prompt
    assert "pre-review audit" in prompt
    assert "SystemDesign_AI_Control.md" in prompt
    assert "Independently verify reuse/replace/new" in prompt
    assert "migration/recovery" in prompt
    assert "redteam-local-codex-trigger" not in prompt
    assert "read-only snapshot" in prompt


def base_refresh_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "action": "REFRESH_BASE",
        "from_phase": "phase-0b",
        "revalidate_phase": "phase-0a",
        "head_sha": HEAD_SHA,
        "target_base_sha": BASE_SHA,
        "prior_pass_reference": PHASE_RECORD_URL,
    }


def base_refresh_status(
    *,
    creator: str = "github-actions[bot]",
    description: str = BASE_REFRESH_STATUS_DESCRIPTION,
    state: str = "success",
    from_phase: str = "phase-0b",
    revalidate_phase: str = "phase-0a",
    target_url: str = PHASE_RECORD_URL,
    target_base_sha: str = DEFAULT_BRANCH_SHA,
) -> dict[str, object]:
    return {
        "context": (
            f"redteam/base-refresh/{from_phase}/{revalidate_phase}/"
            f"{target_base_sha}"
        ),
        "state": state,
        "description": description,
        "target_url": target_url,
        "creator": {"login": creator},
        "url": "https://api.github.com/repos/example/repo/statuses/1",
    }


def base_refresh_checkpoint_status(
    *,
    head_sha: str = REFRESHED_HEAD_SHA,
    previous_head_sha: str = HEAD_SHA,
    target_base_sha: str = DEFAULT_BRANCH_SHA,
    source_phase: str = "phase-0c",
    revalidation_phase: str = "phase-0b",
    authorization_reference: str = f"{PULL_REQUEST_PREFIX}#issuecomment-2",
    creator: str = "github-actions[bot]",
    description: str = BASE_REFRESH_CHECKPOINT_STATUS_DESCRIPTION,
) -> dict[str, object]:
    payload = base_refresh_checkpoint_payload(
        head_sha=head_sha,
        previous_head_sha=previous_head_sha,
        target_base_sha=target_base_sha,
        source_phase=source_phase,
        revalidation_phase=revalidation_phase,
        authorization_reference=authorization_reference,
    )
    return {
        "context": f"{BASE_REFRESH_CHECKPOINT_STATUS_PREFIX}{canonical_digest(payload)}",
        "state": "success",
        "description": description,
        "target_url": authorization_reference,
        "creator": {"login": creator},
        "url": "https://api.github.com/repos/example/repo/statuses/checkpoint",
    }


def test_base_refresh_status_is_strictly_bound_to_workflow_and_sha() -> None:
    evidence = base_refresh_evidence_from_statuses(
        [base_refresh_status()], head_sha=HEAD_SHA
    )

    assert len(evidence) == 1
    assert evidence[0].payload == {
        "schema_version": "1.0",
        "action": "REFRESH_BASE",
        "from_phase": "phase-0b",
        "revalidate_phase": "phase-0a",
        "head_sha": HEAD_SHA,
        "target_base_sha": DEFAULT_BRANCH_SHA,
        "prior_pass_reference": PHASE_RECORD_URL,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("description", "weaker evidence"),
        ("state", "pending"),
    ],
)
def test_malformed_workflow_base_refresh_status_fails_closed(
    field: str, value: str
) -> None:
    status = base_refresh_status()
    status[field] = value

    with pytest.raises(UntrustedEvidenceError, match="status is malformed"):
        base_refresh_evidence_from_statuses([status], head_sha=HEAD_SHA)


def test_untrusted_base_refresh_status_is_ignored() -> None:
    assert (
        base_refresh_evidence_from_statuses(
            [base_refresh_status(creator="attacker")], head_sha=HEAD_SHA
        )
        == []
    )


def test_base_refresh_is_bound_to_adjacent_phase_head_and_default_branch() -> None:
    validate_base_refresh(
        base_refresh_payload(), state=phase_state(), target_base_sha=BASE_SHA
    )


class _AncestorGitHub:
    def __init__(self, ancestors: set[tuple[str, str]]) -> None:
        self.ancestors = ancestors

    def is_ancestor(self, ancestor_sha: str, descendant_sha: str) -> bool:
        return (ancestor_sha, descendant_sha) in self.ancestors


class _StatusGitHub:
    def __init__(self, statuses: dict[str, list[dict[str, object]]]) -> None:
        self.statuses = statuses

    def commit_statuses(self, sha: str) -> list[dict[str, object]]:
        return self.statuses.get(sha, [])


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


def prior_phase_zero_pass() -> MarkerEvidence:
    return MarkerEvidence(
        {"phase": "phase-0a", "verdict": "PASS", "reviewed_sha": HEAD_SHA},
        PHASE_RECORD_URL,
        "github-actions[bot]",
        "",
    )


def test_refreshed_head_discovers_status_from_sha_bound_prior_pass() -> None:
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = _StatusGitHub({HEAD_SHA: [base_refresh_status()]})  # type: ignore[assignment]

    evidence = loop.trusted_base_refresh_statuses(
        refreshed_phase_state(), [prior_phase_zero_pass()]
    )

    assert len(evidence) == 1
    assert evidence[0].payload["head_sha"] == HEAD_SHA
    assert evidence[0].payload["target_base_sha"] == DEFAULT_BRANCH_SHA


class _BaseTransitionGitHub(_StatusGitHub):
    def __init__(self, statuses: dict[str, list[dict[str, object]]]) -> None:
        super().__init__(statuses)
        self.label_calls: list[tuple[int, frozenset[str]]] = []
        self.update_calls: list[tuple[int, str]] = []
        self.workflow_calls: list[tuple[str, str, dict[str, str]]] = []
        self.ancestors: set[tuple[str, str]] = set()
        self.parents: dict[str, tuple[str, ...]] = {
            REFRESHED_HEAD_SHA: (HEAD_SHA, DEFAULT_BRANCH_SHA),
        }

    def set_pull_request_labels(
        self, number: int, labels: frozenset[str]
    ) -> frozenset[str]:
        self.label_calls.append((number, labels))
        return labels

    def update_pull_request_branch(self, number: int, expected_head_sha: str) -> None:
        self.update_calls.append((number, expected_head_sha))

    def dispatch_workflow(
        self, workflow: str, branch: str, inputs: dict[str, str]
    ) -> None:
        self.workflow_calls.append((workflow, branch, inputs))

    def is_ancestor(self, ancestor_sha: str, descendant_sha: str) -> bool:
        return ancestor_sha == descendant_sha or (
            ancestor_sha, descendant_sha
        ) in self.ancestors

    def commit_parents(self, sha: str) -> tuple[str, ...]:
        return self.parents.get(sha, ())

    def compare(self, base_sha: str, head_sha: str) -> dict[str, object]:
        return {"ahead_by": 1}


def test_trusted_status_drives_exact_local_phase_label_rollback() -> None:
    source_state = phase_state(phase="phase-0b")
    expected_state = phase_state(phase="phase-0a")
    github = _BaseTransitionGitHub({HEAD_SHA: [base_refresh_status()]})
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.started_base_label_transitions = set()
    loop.dispatched_base_refreshes = set()
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    observed_states = iter((source_state, expected_state))
    loop.pr_state = lambda: next(observed_states)  # type: ignore[method-assign]
    evidence = loop.trusted_base_refresh_statuses(
        source_state, [prior_phase_zero_pass()]
    )
    loop.current_default_branch_sha = (  # type: ignore[method-assign]
        lambda: DEFAULT_BRANCH_SHA
    )
    loop.live_base_refresh_transition_snapshot = (  # type: ignore[method-assign]
        lambda _state: loop.require_unique_base_refresh_transition_identity(
            source_state, evidence
        )
    )

    assert loop.perform_base_refresh_label_transition(
        source_state, evidence, DEFAULT_BRANCH_SHA
    ) is True
    assert github.label_calls == [(3, expected_state.labels)]
    assert len(loop.started_base_label_transitions) == 1


def test_rolled_back_phase_uses_pending_transition_without_another_rollback() -> None:
    state = phase_state(phase="phase-0a")
    github = _BaseTransitionGitHub({HEAD_SHA: [base_refresh_status()]})
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.started_base_label_transitions = set()
    loop.started_base_updates = set()
    loop.dispatched_base_refreshes = set()
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    evidence = loop.trusted_base_refresh_statuses(state, [prior_phase_zero_pass()])
    observed_states = iter((state, state))
    loop.pr_state = lambda: next(observed_states)  # type: ignore[method-assign]
    loop.current_default_branch_sha = (  # type: ignore[method-assign]
        lambda: DEFAULT_BRANCH_SHA
    )
    loop.live_base_refresh_transition_snapshot = (  # type: ignore[method-assign]
        lambda _state: loop.require_unique_base_refresh_transition_identity(
            state, evidence
        )
    )

    assert loop.perform_base_refresh_label_transition(
        state, evidence, DEFAULT_BRANCH_SHA
    ) is False
    assert loop.perform_pending_base_refresh(
        state, evidence, DEFAULT_BRANCH_SHA
    ) is True
    assert github.label_calls == []
    assert github.update_calls == [(3, HEAD_SHA)]


def test_conflicting_source_and_restart_transitions_fail_closed() -> None:
    state = phase_state(phase="phase-0b")
    statuses = [
        base_refresh_status(),
        base_refresh_status(
            from_phase="phase-0c",
            revalidate_phase="phase-0b",
            target_url=PHASE_ONE_RECORD_URL,
        ),
    ]
    github = _BaseTransitionGitHub({HEAD_SHA: statuses})
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.started_base_label_transitions = set()
    loop.started_base_updates = set()
    loop.dispatched_base_refreshes = set()
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    phase_one_pass = MarkerEvidence(
        {"phase": "phase-0b", "verdict": "PASS", "reviewed_sha": HEAD_SHA},
        PHASE_ONE_RECORD_URL,
        "github-actions[bot]",
        "",
    )
    evidence = loop.trusted_base_refresh_statuses(
        state, [prior_phase_zero_pass(), phase_one_pass]
    )

    for operation in (
        loop.perform_base_refresh_label_transition,
        loop.perform_pending_base_refresh,
    ):
        with pytest.raises(UntrustedEvidenceError, match="conflicting"):
            operation(state, evidence, DEFAULT_BRANCH_SHA)

    assert github.label_calls == []
    assert github.update_calls == []


@pytest.mark.parametrize("operation_name", ["label", "update"])
@pytest.mark.parametrize("drift_stage", ["before", "after"])
def test_base_refresh_status_race_fails_closed_around_local_side_effects(
    operation_name: str, drift_stage: str
) -> None:
    state = phase_state(phase="phase-0b")
    source_records = base_refresh_evidence_from_statuses(
        [base_refresh_status()], head_sha=HEAD_SHA
    )
    restart_records = base_refresh_evidence_from_statuses(
        [
            base_refresh_status(
                from_phase="phase-0c",
                revalidate_phase="phase-0b",
                target_url=PHASE_ONE_RECORD_URL,
            )
        ],
        head_sha=HEAD_SHA,
    )
    initial_records = (
        source_records if operation_name == "label" else restart_records
    )
    conflicting_records = source_records + restart_records
    initial_snapshot = PhaseLoop.require_unique_base_refresh_transition_identity(
        state, initial_records
    )
    snapshots = (
        iter((conflicting_records,))
        if drift_stage == "before"
        else iter((initial_records, conflicting_records))
    )
    github = _BaseTransitionGitHub({})
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.started_base_label_transitions = set()
    loop.started_base_updates = set()
    loop.dispatched_base_refreshes = set()
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    expected_label_state = phase_state(phase="phase-0a")
    states = (
        iter((state,))
        if drift_stage == "before"
        else (
            iter((state, expected_label_state))
            if operation_name == "label"
            else iter((state, state))
        )
    )
    loop.pr_state = lambda: next(states)  # type: ignore[method-assign]
    loop.current_default_branch_sha = (  # type: ignore[method-assign]
        lambda: DEFAULT_BRANCH_SHA
    )
    loop.live_base_refresh_transition_snapshot = (  # type: ignore[method-assign]
        lambda _state: loop.require_unique_base_refresh_transition_identity(
            state, next(snapshots)
        )
    )
    operation = (
        loop.perform_base_refresh_label_transition
        if operation_name == "label"
        else loop.perform_pending_base_refresh
    )

    with pytest.raises(UntrustedEvidenceError, match="conflicting"):
        operation(state, initial_records, DEFAULT_BRANCH_SHA)

    expected_writes = 0 if drift_stage == "before" else 1
    assert len(github.label_calls) == (
        expected_writes if operation_name == "label" else 0
    )
    assert len(github.update_calls) == (
        expected_writes if operation_name == "update" else 0
    )
    assert initial_snapshot


def test_higher_phase_post_label_snapshot_uses_rolled_back_phase() -> None:
    state = phase_state(phase="phase-1")
    expected_state = phase_state(phase="phase-0c")
    authorized_records = base_refresh_evidence_from_statuses(
        [
            base_refresh_status(
                from_phase="phase-1",
                revalidate_phase="phase-0c",
                target_url=PHASE_ZERO_C_RECORD_URL,
            )
        ],
        head_sha=HEAD_SHA,
    )
    lower_source_records = base_refresh_evidence_from_statuses(
        [
            base_refresh_status(
                from_phase="phase-0c",
                revalidate_phase="phase-0b",
                target_url=PHASE_ZERO_B_RECORD_URL,
            )
        ],
        head_sha=HEAD_SHA,
    )
    transition_snapshot = PhaseLoop.require_unique_base_refresh_transition_identity(
        state, authorized_records
    )
    github = _BaseTransitionGitHub({})
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.started_base_label_transitions = set()
    loop.dispatched_base_refreshes = set()
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    observed_states = iter((state, expected_state))
    loop.pr_state = lambda: next(observed_states)  # type: ignore[method-assign]
    loop.current_default_branch_sha = (  # type: ignore[method-assign]
        lambda: DEFAULT_BRANCH_SHA
    )
    observed_snapshot_phases: list[str] = []

    def live_snapshot(snapshot_state: PullRequestState) -> frozenset[str]:
        observed_snapshot_phases.append(snapshot_state.phase)
        records = (
            authorized_records
            if snapshot_state.phase == state.phase
            else authorized_records + lower_source_records
        )
        return loop.require_unique_base_refresh_transition_identity(
            snapshot_state, records
        )

    loop.live_base_refresh_transition_snapshot = live_snapshot  # type: ignore[method-assign]

    with pytest.raises(UntrustedEvidenceError, match="conflicting"):
        loop.perform_base_refresh_label_transition(
            state, authorized_records, DEFAULT_BRANCH_SHA
        )

    assert github.label_calls == [(3, expected_state.labels)]
    assert observed_snapshot_phases == ["phase-1", "phase-0c"]
    assert transition_snapshot
    assert loop.started_base_label_transitions == set()


def test_base_refresh_rejects_post_update_pr_state_drift() -> None:
    state = phase_state(phase="phase-0b")
    drifted_state = PullRequestState(
        number=state.number,
        head_sha=state.head_sha,
        base_sha=state.base_sha,
        base_ref=state.base_ref,
        phase="phase-0a",
        labels=frozenset({"ai-loop", "ai-needs-implementation", "phase-0a"}),
        state=state.state,
        head_repository=state.head_repository,
    )
    records = base_refresh_evidence_from_statuses(
        [
            base_refresh_status(
                from_phase="phase-0c",
                revalidate_phase="phase-0b",
                target_url=PHASE_ONE_RECORD_URL,
            )
        ],
        head_sha=HEAD_SHA,
    )
    snapshot = PhaseLoop.require_unique_base_refresh_transition_identity(
        state, records
    )
    github = _BaseTransitionGitHub({})
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.started_base_updates = set()
    loop.dispatched_base_refreshes = set()
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    observed_states = iter((state, drifted_state))
    loop.pr_state = lambda: next(observed_states)  # type: ignore[method-assign]
    loop.current_default_branch_sha = (  # type: ignore[method-assign]
        lambda: DEFAULT_BRANCH_SHA
    )
    loop.live_base_refresh_transition_snapshot = (  # type: ignore[method-assign]
        lambda _state: snapshot
    )

    with pytest.raises(UntrustedEvidenceError, match="metadata changed"):
        loop.perform_pending_base_refresh(state, records, DEFAULT_BRANCH_SHA)

    assert github.update_calls == [(3, HEAD_SHA)]
    assert loop.started_base_updates == set()


def test_base_refresh_accepts_exact_authorized_refreshed_ancestry() -> None:
    state = phase_state(phase="phase-0b")
    refreshed_state = PullRequestState(
        number=state.number,
        head_sha=REFRESHED_HEAD_SHA,
        base_sha=DEFAULT_BRANCH_SHA,
        base_ref=state.base_ref,
        phase=state.phase,
        labels=state.labels,
        state=state.state,
        head_repository=state.head_repository,
    )
    records = base_refresh_evidence_from_statuses(
        [
            base_refresh_status(
                from_phase="phase-0c",
                revalidate_phase="phase-0b",
                target_url=PHASE_ONE_RECORD_URL,
            )
        ],
        head_sha=HEAD_SHA,
    )
    snapshot = PhaseLoop.require_unique_base_refresh_transition_identity(
        state, records
    )
    github = _BaseTransitionGitHub({})
    github.ancestors = {
        (HEAD_SHA, REFRESHED_HEAD_SHA),
        (DEFAULT_BRANCH_SHA, REFRESHED_HEAD_SHA),
    }
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.started_base_updates = set()
    loop.dispatched_base_refreshes = set()
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    observed_states = iter((state, refreshed_state))
    loop.pr_state = lambda: next(observed_states)  # type: ignore[method-assign]
    loop.current_default_branch_sha = (  # type: ignore[method-assign]
        lambda: DEFAULT_BRANCH_SHA
    )
    loop.live_base_refresh_transition_snapshot = (  # type: ignore[method-assign]
        lambda _state: snapshot
    )

    assert loop.perform_pending_base_refresh(
        state, records, DEFAULT_BRANCH_SHA
    ) is True
    assert github.update_calls == [(3, HEAD_SHA)]
    assert len(loop.started_base_updates) == 1


def test_local_phase_label_rollback_fails_closed_on_concurrent_pr_drift() -> None:
    source_state = phase_state(phase="phase-0b")
    drifted_state = PullRequestState(
        number=source_state.number,
        head_sha="c" * 40,
        base_sha=source_state.base_sha,
        base_ref=source_state.base_ref,
        phase="phase-0a",
        labels=frozenset({"ai-loop", "ai-needs-implementation", "phase-0a"}),
        state=source_state.state,
        head_repository=source_state.head_repository,
    )
    github = _BaseTransitionGitHub({HEAD_SHA: [base_refresh_status()]})
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.started_base_label_transitions = set()
    loop.dispatched_base_refreshes = set()
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    loop.pr_state = lambda: drifted_state  # type: ignore[method-assign]
    evidence = loop.trusted_base_refresh_statuses(
        source_state, [prior_phase_zero_pass()]
    )

    with pytest.raises(UntrustedEvidenceError, match="changed before"):
        loop.perform_base_refresh_label_transition(
            source_state, evidence, DEFAULT_BRANCH_SHA
        )

    assert github.label_calls == []
    assert loop.started_base_label_transitions == set()


def test_local_phase_label_rollback_fails_closed_on_post_write_pr_drift() -> None:
    source_state = phase_state(phase="phase-0b")
    drifted_state = PullRequestState(
        number=source_state.number,
        head_sha="c" * 40,
        base_sha=source_state.base_sha,
        base_ref=source_state.base_ref,
        phase="phase-0a",
        labels=frozenset({"ai-loop", "ai-needs-implementation", "phase-0a"}),
        state=source_state.state,
        head_repository=source_state.head_repository,
    )
    github = _BaseTransitionGitHub({HEAD_SHA: [base_refresh_status()]})
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.started_base_label_transitions = set()
    loop.dispatched_base_refreshes = set()
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    observed_states = iter((source_state, drifted_state))
    loop.pr_state = lambda: next(observed_states)  # type: ignore[method-assign]
    evidence = loop.trusted_base_refresh_statuses(
        source_state, [prior_phase_zero_pass()]
    )
    loop.current_default_branch_sha = (  # type: ignore[method-assign]
        lambda: DEFAULT_BRANCH_SHA
    )
    loop.live_base_refresh_transition_snapshot = (  # type: ignore[method-assign]
        lambda _state: loop.require_unique_base_refresh_transition_identity(
            source_state, evidence
        )
    )

    with pytest.raises(UntrustedEvidenceError, match="changed during"):
        loop.perform_base_refresh_label_transition(
            source_state, evidence, DEFAULT_BRANCH_SHA
        )

    assert github.label_calls == [(3, phase_state(phase="phase-0a").labels)]
    assert loop.started_base_label_transitions == set()


def test_base_refresh_status_without_referenced_prior_pass_fails_closed() -> None:
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = _StatusGitHub({HEAD_SHA: [base_refresh_status()]})  # type: ignore[assignment]

    with pytest.raises(UntrustedEvidenceError, match="not bound to trusted Phase evidence"):
        loop.trusted_base_refresh_statuses(phase_state(), [])


def blocked_refresh_records() -> tuple[MarkerEvidence, MarkerEvidence]:
    base_pass, gate = chained_phase_passes()[:2]
    gate.payload.update(
        {
            "reviewed_sha": HEAD_SHA,
            "base_sha": base_pass.payload["reviewed_sha"],
            "verdict": "CHANGES_REQUESTED",
            "finding_key": "CODEX-P1-ATOMIC-DISPATCH",
            "loop_state": "BLOCKED_LIMIT",
        }
    )
    return base_pass, gate


def design_stop_refresh_records() -> tuple[MarkerEvidence, MarkerEvidence]:
    base_pass, gate = blocked_refresh_records()
    gate.payload.update(
        {
            "schema_version": "1.1",
            "stop_reason": "INVARIANT_FAMILY_RECURRENCE",
            "recurring_families": ["authorization-lifecycle"],
            "finding_references": [f"{PULL_REQUEST_PREFIX}#discussion_r123"],
        }
    )
    return base_pass, gate


def blocked_phase_state() -> PullRequestState:
    state = phase_state(phase="phase-0b")
    return replace(
        state,
        labels=frozenset({"ai-loop", "ai-needs-implementation", "phase-0b"}),
    )


def blocked_refresh_loop(
    statuses: dict[str, list[dict[str, object]]],
) -> tuple[PhaseLoop, _BaseTransitionGitHub]:
    base_pass, _gate = blocked_refresh_records()
    github = _BaseTransitionGitHub(statuses)
    github.repository = "example/repo"  # type: ignore[attr-defined]
    github.ancestors = {(str(base_pass.payload["reviewed_sha"]), HEAD_SHA)}
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.pull_request_number = 3
    loop.reviewer_login = REVIEWER_LOGIN
    loop.approver_login = ACTOR_LOGIN
    return loop, github


def test_blocked_current_phase_gate_authorizes_exact_base_refresh() -> None:
    base_pass, gate = blocked_refresh_records()
    status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    loop, _github = blocked_refresh_loop({HEAD_SHA: [status]})

    evidence = loop.trusted_base_refresh_statuses(
        blocked_phase_state(), [base_pass, gate]
    )

    assert len(evidence) == 1
    assert evidence[0].payload["prior_pass_reference"] == gate.url
    assert loop.blocked_base_refresh_candidate(
        blocked_phase_state(), [base_pass, gate], DEFAULT_BRANCH_SHA
    ) == gate


def test_blocked_current_phase_gate_accepts_identical_trusted_duplicates() -> None:
    base_pass, gate = blocked_refresh_records()
    duplicate = MarkerEvidence(
        dict(gate.payload),
        f"{gate.url}-duplicate",
        gate.author,
        gate.body,
    )
    loop, _github = blocked_refresh_loop({})

    assert loop.blocked_base_refresh_candidate(
        blocked_phase_state(),
        [base_pass, gate, duplicate],
        DEFAULT_BRANCH_SHA,
    ) == duplicate


def test_refreshed_blocked_gate_authorizes_another_exact_base_refresh() -> None:
    base_pass, gate = design_stop_refresh_records()
    first_status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    checkpoint = base_refresh_checkpoint_status(authorization_reference=gate.url)
    loop, github = blocked_refresh_loop(
        {HEAD_SHA: [first_status], REFRESHED_HEAD_SHA: [checkpoint]}
    )
    github.ancestors.add((HEAD_SHA, REFRESHED_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        base_sha=DEFAULT_BRANCH_SHA,
        labels=frozenset(
            {"ai-loop", "ai-loop-blocked", "ai-needs-review", "phase-0b"}
        ),
    )

    assert loop.blocked_base_refresh_candidate(
        state, [base_pass, gate], SECOND_DEFAULT_BRANCH_SHA
    ) == gate


def test_checkpointed_normal_blocker_authorizes_another_exact_base_refresh() -> None:
    base_pass, gate = blocked_refresh_records()
    checkpoint = base_refresh_checkpoint_status(authorization_reference=gate.url)
    loop, github = blocked_refresh_loop({REFRESHED_HEAD_SHA: [checkpoint]})
    github.ancestors.add((HEAD_SHA, REFRESHED_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        base_sha=DEFAULT_BRANCH_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )

    assert loop.blocked_base_refresh_candidate(
        state, [base_pass, gate], SECOND_DEFAULT_BRANCH_SHA
    ) == gate


def test_checkpoint_binds_next_prepared_refresh_to_inherited_gate() -> None:
    base_pass, gate = design_stop_refresh_records()
    first_status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    checkpoint = base_refresh_checkpoint_status(authorization_reference=gate.url)
    next_status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
        target_base_sha=SECOND_DEFAULT_BRANCH_SHA,
    )
    loop, github = blocked_refresh_loop(
        {
            HEAD_SHA: [first_status],
            REFRESHED_HEAD_SHA: [checkpoint, next_status],
        }
    )
    github.ancestors.add((HEAD_SHA, REFRESHED_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        base_sha=DEFAULT_BRANCH_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )

    evidence = loop.trusted_base_refresh_statuses(state, [base_pass, gate])

    assert any(
        record.payload["head_sha"] == REFRESHED_HEAD_SHA
        and record.payload["target_base_sha"] == SECOND_DEFAULT_BRANCH_SHA
        for record in evidence
    )


def test_design_approved_implementation_output_does_not_require_checkpoint() -> None:
    base_pass, gate = design_stop_refresh_records()
    first_status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    loop, github = blocked_refresh_loop({HEAD_SHA: [first_status]})
    github.ancestors.add((HEAD_SHA, IMPLEMENTATION_OUTPUT_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=IMPLEMENTATION_OUTPUT_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-needs-review", "phase-0b"}),
    )

    evidence = loop.trusted_base_refresh_statuses(state, [base_pass, gate])

    assert len(evidence) == 1
    assert evidence[0].payload["head_sha"] == HEAD_SHA


def test_normal_output_cannot_inherit_gate_for_another_refresh() -> None:
    base_pass, gate = design_stop_refresh_records()
    next_status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
        target_base_sha=SECOND_DEFAULT_BRANCH_SHA,
    )
    loop, github = blocked_refresh_loop(
        {IMPLEMENTATION_OUTPUT_HEAD_SHA: [next_status]}
    )
    github.ancestors.add((HEAD_SHA, IMPLEMENTATION_OUTPUT_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=IMPLEMENTATION_OUTPUT_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-needs-review", "phase-0b"}),
    )

    with pytest.raises(UntrustedEvidenceError, match="not bound to trusted Phase evidence"):
        loop.trusted_base_refresh_statuses(state, [base_pass, gate])


def test_only_a_design_stop_gate_can_authorize_a_later_refresh() -> None:
    base_pass, gate = blocked_refresh_records()
    first_status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    loop, github = blocked_refresh_loop({HEAD_SHA: [first_status]})
    github.ancestors.add((HEAD_SHA, REFRESHED_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )

    assert (
        loop.blocked_base_refresh_candidate(
            state, [base_pass, gate], SECOND_DEFAULT_BRANCH_SHA
        )
        is None
    )


def test_current_head_checkpoint_replaces_historical_chain_walk() -> None:
    base_pass, gate = design_stop_refresh_records()
    current_checkpoint = base_refresh_checkpoint_status(
        head_sha=SECOND_REFRESHED_HEAD_SHA,
        previous_head_sha=REFRESHED_HEAD_SHA,
        target_base_sha=SECOND_DEFAULT_BRANCH_SHA,
        authorization_reference=gate.url,
    )
    loop, github = blocked_refresh_loop(
        {SECOND_REFRESHED_HEAD_SHA: [current_checkpoint]}
    )
    github.parents[SECOND_REFRESHED_HEAD_SHA] = (
        REFRESHED_HEAD_SHA,
        SECOND_DEFAULT_BRANCH_SHA,
    )
    github.ancestors.update(
        {
            (HEAD_SHA, REFRESHED_HEAD_SHA),
            (HEAD_SHA, SECOND_REFRESHED_HEAD_SHA),
            (REFRESHED_HEAD_SHA, SECOND_REFRESHED_HEAD_SHA),
        }
    )
    state = replace(
        blocked_phase_state(),
        head_sha=SECOND_REFRESHED_HEAD_SHA,
        base_sha=SECOND_DEFAULT_BRANCH_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )

    evidence = loop.trusted_base_refresh_checkpoint(
        head_sha=state.head_sha,
        phase=state.phase,
        gate=gate,
    )

    assert evidence is not None
    assert evidence.payload["previous_head_sha"] == REFRESHED_HEAD_SHA
    assert evidence.payload["target_base_sha"] == SECOND_DEFAULT_BRANCH_SHA


def test_latest_gate_uses_current_checkpoint_without_historical_gate_walk() -> None:
    base_pass, gate = blocked_refresh_records()
    checkpoint = base_refresh_checkpoint_status(authorization_reference=gate.url)
    loop, github = blocked_refresh_loop({REFRESHED_HEAD_SHA: [checkpoint]})
    calls: list[tuple[str, str]] = []
    original_is_ancestor = github.is_ancestor

    def counted_is_ancestor(ancestor_sha: str, descendant_sha: str) -> bool:
        calls.append((ancestor_sha, descendant_sha))
        return original_is_ancestor(ancestor_sha, descendant_sha)

    github.is_ancestor = counted_is_ancestor  # type: ignore[method-assign]
    state = replace(blocked_phase_state(), head_sha=REFRESHED_HEAD_SHA)

    assert loop.latest_incorporated_phase_gate(state, [base_pass, gate]) == gate
    assert (HEAD_SHA, REFRESHED_HEAD_SHA) not in calls


def test_latest_gate_fallback_scales_linearly_for_a_linear_history() -> None:
    heads = [f"{index:040x}" for index in range(1, 31)]
    current_head = f"{31:040x}"
    rank = {head: index for index, head in enumerate([*heads, current_head])}
    calls: list[tuple[str, str]] = []

    class RankedGitHub:
        def commit_statuses(self, _sha: str) -> list[dict[str, object]]:
            return []

        def is_ancestor(self, ancestor_sha: str, descendant_sha: str) -> bool:
            calls.append((ancestor_sha, descendant_sha))
            return rank[ancestor_sha] <= rank[descendant_sha]

    records = [
        MarkerEvidence(
            {"phase": "phase-0b", "reviewed_sha": head},
            f"{PULL_REQUEST_PREFIX}#issuecomment-linear-{index}",
            "github-actions[bot]",
            "",
        )
        for index, head in enumerate(heads)
    ]
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = RankedGitHub()  # type: ignore[assignment]
    state = replace(blocked_phase_state(), head_sha=current_head)

    assert loop.latest_incorporated_phase_gate(state, records) == records[-1]
    assert len(calls) < len(records) * 4


def test_completed_refresh_without_checkpoint_awaits_confirmation() -> None:
    base_pass, gate = design_stop_refresh_records()
    prepared = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    loop, github = blocked_refresh_loop({HEAD_SHA: [prepared]})
    github.ancestors.add((HEAD_SHA, REFRESHED_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )

    pending = loop.pending_base_refresh_checkpoint(state, [base_pass, gate])

    assert pending == (gate, HEAD_SHA, DEFAULT_BRANCH_SHA)


def test_completed_blocked_refresh_repairs_missing_stop_projection() -> None:
    base_pass, gate = blocked_refresh_records()
    prepared = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    loop, github = blocked_refresh_loop({HEAD_SHA: [prepared]})
    github.ancestors.add((HEAD_SHA, REFRESHED_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-needs-implementation", "phase-0b"}),
    )

    pending = loop.pending_base_refresh_checkpoint(state, [base_pass, gate])

    assert pending == (gate, HEAD_SHA, DEFAULT_BRANCH_SHA)


def test_prepared_blocked_refresh_restores_stop_latch_before_branch_update() -> None:
    base_pass, gate = blocked_refresh_records()
    prepared_status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    loop, github = blocked_refresh_loop({HEAD_SHA: [prepared_status]})
    state = blocked_phase_state()
    expected_state = replace(
        state,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )
    records = loop.trusted_base_refresh_statuses(state, [base_pass, gate])
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    observed_states = iter((state, expected_state))
    loop.pr_state = lambda: next(observed_states)  # type: ignore[method-assign]
    loop.current_default_branch_sha = (  # type: ignore[method-assign]
        lambda: DEFAULT_BRANCH_SHA
    )
    loop.live_base_refresh_transition_snapshot = (  # type: ignore[method-assign]
        lambda _state: loop.require_unique_base_refresh_transition_identity(
            state, records
        )
    )

    assert loop.repair_prepared_blocked_refresh_projection(
        state, [base_pass, gate], records, DEFAULT_BRANCH_SHA
    ) is True
    assert github.label_calls == [(3, expected_state.labels)]
    assert github.update_calls == []


def test_prior_pass_base_refresh_does_not_restore_blocked_projection() -> None:
    phase_pass = chained_phase_passes()[1]
    prepared_status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=phase_pass.url,
    )
    loop, github = blocked_refresh_loop({HEAD_SHA: [prepared_status]})
    state = blocked_phase_state()
    records = base_refresh_evidence_from_statuses(
        [prepared_status], head_sha=HEAD_SHA
    )

    assert loop.repair_prepared_blocked_refresh_projection(
        state, [phase_pass], records, DEFAULT_BRANCH_SHA
    ) is False
    assert github.label_calls == []


def test_applied_blocked_refresh_restores_stop_latch_before_confirmation() -> None:
    base_pass, gate = blocked_refresh_records()
    prepared = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    loop, github = blocked_refresh_loop({HEAD_SHA: [prepared]})
    github.ancestors.add((HEAD_SHA, REFRESHED_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-needs-implementation", "phase-0b"}),
    )
    expected_state = replace(
        state,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )
    pending = loop.pending_base_refresh_checkpoint(state, [base_pass, gate])
    assert pending is not None
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    observed_states = iter((state, expected_state))
    loop.pr_state = lambda: next(observed_states)  # type: ignore[method-assign]

    assert loop.repair_applied_blocked_refresh_projection(
        state, [base_pass, gate], pending
    ) is True
    assert github.label_calls == [(3, expected_state.labels)]


def test_applied_blocked_refresh_projection_fails_closed_on_pr_drift() -> None:
    base_pass, gate = blocked_refresh_records()
    prepared = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    loop, github = blocked_refresh_loop({HEAD_SHA: [prepared]})
    github.ancestors.add((HEAD_SHA, REFRESHED_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-needs-implementation", "phase-0b"}),
    )
    pending = loop.pending_base_refresh_checkpoint(state, [base_pass, gate])
    assert pending is not None
    drifted_state = replace(
        state,
        head_sha=IMPLEMENTATION_OUTPUT_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    observed_states = iter((state, drifted_state))
    loop.pr_state = lambda: next(observed_states)  # type: ignore[method-assign]

    with pytest.raises(UntrustedEvidenceError, match="changed during"):
        loop.repair_applied_blocked_refresh_projection(
            state, [base_pass, gate], pending
        )
    assert github.label_calls == [
        (3, frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}))
    ]


def test_unblocked_non_refresh_output_does_not_request_a_checkpoint() -> None:
    base_pass, gate = blocked_refresh_records()
    loop, _github = blocked_refresh_loop({})
    state = replace(
        blocked_phase_state(),
        head_sha=IMPLEMENTATION_OUTPUT_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-needs-implementation", "phase-0b"}),
    )

    assert loop.pending_base_refresh_checkpoint(state, [base_pass, gate]) is None


def test_unblocked_prior_pass_refresh_is_not_a_blocker_checkpoint() -> None:
    base_pass, gate = blocked_refresh_records()
    prepared = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=base_pass.url,
    )
    loop, github = blocked_refresh_loop({HEAD_SHA: [prepared]})
    github.ancestors.add((HEAD_SHA, REFRESHED_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-needs-implementation", "phase-0b"}),
    )

    assert loop.pending_base_refresh_checkpoint(state, [base_pass, gate]) is None


def test_pending_checkpoint_dispatches_one_exact_confirmation() -> None:
    _base_pass, gate = design_stop_refresh_records()
    loop, github = blocked_refresh_loop({})
    state = replace(blocked_phase_state(), head_sha=REFRESHED_HEAD_SHA)
    loop.default_branch = "main"
    loop.dispatched_base_refresh_confirmations = set()
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]

    loop.request_base_refresh_confirmation(
        state,
        gate,
        previous_head_sha=HEAD_SHA,
        target_base_sha=DEFAULT_BRANCH_SHA,
    )
    loop.request_base_refresh_confirmation(
        state,
        gate,
        previous_head_sha=HEAD_SHA,
        target_base_sha=DEFAULT_BRANCH_SHA,
    )

    assert github.workflow_calls == [
        (
            "refresh-ai-loop-base.yml",
            "main",
            {
                "pull_request_number": "3",
                "source_phase": "phase-0c",
                "expected_head_sha": REFRESHED_HEAD_SHA,
                "previous_head_sha": HEAD_SHA,
                "target_base_sha": DEFAULT_BRANCH_SHA,
                "prior_pass_reference": gate.url,
                "confirmation": "CONFIRM_AI_LOOP_BASE_REFRESH",
            },
        )
    ]


def test_checkpoint_confirmation_rejects_a_non_merge_commit() -> None:
    base_pass, gate = design_stop_refresh_records()
    loop, github = blocked_refresh_loop({})
    github.parents[REFRESHED_HEAD_SHA] = (HEAD_SHA,)
    github.ancestors.add((HEAD_SHA, REFRESHED_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )

    with pytest.raises(UntrustedEvidenceError, match="two-parent merge"):
        loop.pending_base_refresh_checkpoint(state, [base_pass, gate])


def test_second_refresh_rejects_a_missing_previous_checkpoint() -> None:
    base_pass, gate = design_stop_refresh_records()
    next_status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
        target_base_sha=SECOND_DEFAULT_BRANCH_SHA,
    )
    loop, github = blocked_refresh_loop({REFRESHED_HEAD_SHA: [next_status]})
    github.parents[SECOND_REFRESHED_HEAD_SHA] = (
        REFRESHED_HEAD_SHA,
        SECOND_DEFAULT_BRANCH_SHA,
    )
    github.ancestors.add((HEAD_SHA, SECOND_REFRESHED_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=SECOND_REFRESHED_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )

    with pytest.raises(UntrustedEvidenceError, match="previous HEAD lacks"):
        loop.pending_base_refresh_checkpoint(state, [base_pass, gate])


def test_checkpointed_normal_blocker_can_confirm_the_next_refresh() -> None:
    base_pass, gate = blocked_refresh_records()
    checkpoint = base_refresh_checkpoint_status(authorization_reference=gate.url)
    next_status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
        target_base_sha=SECOND_DEFAULT_BRANCH_SHA,
    )
    loop, github = blocked_refresh_loop(
        {REFRESHED_HEAD_SHA: [checkpoint, next_status]}
    )
    github.parents[SECOND_REFRESHED_HEAD_SHA] = (
        REFRESHED_HEAD_SHA,
        SECOND_DEFAULT_BRANCH_SHA,
    )
    state = replace(
        blocked_phase_state(),
        head_sha=SECOND_REFRESHED_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )

    pending = loop.pending_base_refresh_checkpoint(state, [base_pass, gate])

    assert pending == (gate, REFRESHED_HEAD_SHA, SECOND_DEFAULT_BRANCH_SHA)


def test_first_refresh_confirmation_rejects_missing_previous_authorization() -> None:
    base_pass, gate = design_stop_refresh_records()
    loop, github = blocked_refresh_loop({})
    github.ancestors.add((HEAD_SHA, REFRESHED_HEAD_SHA))
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )

    with pytest.raises(UntrustedEvidenceError, match="previous-HEAD authorization"):
        loop.pending_base_refresh_checkpoint(state, [base_pass, gate])


def test_checkpoint_digest_rejects_parent_or_gate_mismatch() -> None:
    status = base_refresh_checkpoint_status()

    with pytest.raises(UntrustedEvidenceError, match="checkpoint is malformed"):
        base_refresh_checkpoint_from_statuses(
            [status],
            head_sha=REFRESHED_HEAD_SHA,
            previous_head_sha=HEAD_SHA,
            target_base_sha=SECOND_DEFAULT_BRANCH_SHA,
            source_phase="phase-0c",
            revalidation_phase="phase-0b",
            authorization_reference=f"{PULL_REQUEST_PREFIX}#issuecomment-2",
        )


def test_blocked_current_phase_gate_rejects_distinct_trusted_duplicates() -> None:
    base_pass, gate = blocked_refresh_records()
    conflicting_payload = dict(gate.payload)
    conflicting_payload["finding_key"] = "CODEX-P1-DISTINCT-FINDING"
    conflicting = MarkerEvidence(
        conflicting_payload,
        f"{gate.url}-conflicting",
        gate.author,
        gate.body,
    )
    loop, _github = blocked_refresh_loop({})

    with pytest.raises(UntrustedEvidenceError, match="ambiguous current-head"):
        loop.blocked_base_refresh_candidate(
            blocked_phase_state(),
            [base_pass, gate, conflicting],
            DEFAULT_BRANCH_SHA,
        )


def test_blocked_current_phase_refresh_rejects_missing_adjacent_base_pass() -> None:
    _base_pass, gate = blocked_refresh_records()
    status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    loop, _github = blocked_refresh_loop({HEAD_SHA: [status]})

    with pytest.raises(UntrustedEvidenceError, match="adjacent PASS"):
        loop.trusted_base_refresh_statuses(blocked_phase_state(), [gate])


def test_fresh_blocked_gate_routes_before_post_refresh_checkpoint() -> None:
    base_pass, gate = blocked_refresh_records()
    loop, _github = blocked_refresh_loop({})

    assert loop.perform_post_blocked_refresh_resume(
        blocked_phase_state(), [], [base_pass, gate], [], DEFAULT_BRANCH_SHA
    ) is False


def test_latest_gate_supersedes_consumed_design_stop_for_post_refresh_routing() -> None:
    base_pass, design_stop = design_stop_refresh_records()
    _same_base, latest_gate = blocked_refresh_records()
    latest_gate = MarkerEvidence(
        {**latest_gate.payload, "reviewed_sha": IMPLEMENTATION_OUTPUT_HEAD_SHA},
        f"{PULL_REQUEST_PREFIX}#issuecomment-latest-gate",
        latest_gate.author,
        latest_gate.body,
    )
    loop, github = blocked_refresh_loop({})
    github.ancestors.update(
        {
            (HEAD_SHA, IMPLEMENTATION_OUTPUT_HEAD_SHA),
            (str(base_pass.payload["reviewed_sha"]), IMPLEMENTATION_OUTPUT_HEAD_SHA),
        }
    )
    state = replace(
        blocked_phase_state(),
        head_sha=IMPLEMENTATION_OUTPUT_HEAD_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )

    assert loop.perform_post_blocked_refresh_resume(
        state,
        [],
        [base_pass, design_stop, latest_gate],
        [],
        DEFAULT_BRANCH_SHA,
    ) is False


def test_refreshed_blocked_phase_dispatches_one_bounded_resume() -> None:
    base_pass, gate = blocked_refresh_records()
    status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    checkpoint = base_refresh_checkpoint_status(authorization_reference=gate.url)
    loop, github = blocked_refresh_loop(
        {HEAD_SHA: [status], REFRESHED_HEAD_SHA: [checkpoint]}
    )
    github.ancestors.update(
        {(HEAD_SHA, REFRESHED_HEAD_SHA), (DEFAULT_BRANCH_SHA, REFRESHED_HEAD_SHA)}
    )
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        base_sha=DEFAULT_BRANCH_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )
    loop.default_branch = "main"
    loop.dispatched_blocked_resumes = set()
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    loop.check_state = lambda _head: "success"  # type: ignore[method-assign]

    assert loop.perform_post_blocked_refresh_resume(
        state, [], [base_pass, gate], [], DEFAULT_BRANCH_SHA
    ) is True
    assert len(github.workflow_calls) == 1
    workflow, branch, inputs = github.workflow_calls[0]
    assert (workflow, branch) == ("resume-ai-loop.yml", "main")
    assert inputs["head_sha"] == REFRESHED_HEAD_SHA
    assert inputs["resolution_reference"] == gate.url

    assert loop.perform_post_blocked_refresh_resume(
        state, [], [base_pass, gate], [], DEFAULT_BRANCH_SHA
    ) is True
    assert len(github.workflow_calls) == 1


def test_refreshed_design_stop_never_dispatches_generic_resume() -> None:
    base_pass, gate = blocked_refresh_records()
    prior_review_sha = "9" * 40
    prior_family = MarkerEvidence(
        {
            "schema_version": "1.0",
            "phase": "phase-0b",
            "reviewed_sha": prior_review_sha,
            "review_reference": f"{PULL_REQUEST_PREFIX}#pullrequestreview-8",
            "verdict": "CHANGES_REQUESTED",
            "families": ["authorization-lifecycle"],
        },
        f"{PULL_REQUEST_PREFIX}#issuecomment-family-8",
        "github-actions[bot]",
        "",
    )
    current_family = MarkerEvidence(
        {
            "schema_version": "1.0",
            "phase": "phase-0b",
            "reviewed_sha": HEAD_SHA,
            "review_reference": gate.payload["review_reference"],
            "verdict": "CHANGES_REQUESTED",
            "families": ["authorization-lifecycle"],
        },
        f"{PULL_REQUEST_PREFIX}#issuecomment-family-9",
        "github-actions[bot]",
        "",
    )
    status = base_refresh_status(
        from_phase="phase-0c",
        revalidate_phase="phase-0b",
        target_url=gate.url,
    )
    checkpoint = base_refresh_checkpoint_status(authorization_reference=gate.url)
    loop, github = blocked_refresh_loop(
        {HEAD_SHA: [status], REFRESHED_HEAD_SHA: [checkpoint]}
    )
    github.ancestors.update(
        {
            (prior_review_sha, HEAD_SHA),
            (HEAD_SHA, REFRESHED_HEAD_SHA),
            (DEFAULT_BRANCH_SHA, REFRESHED_HEAD_SHA),
        }
    )
    state = replace(
        blocked_phase_state(),
        head_sha=REFRESHED_HEAD_SHA,
        base_sha=DEFAULT_BRANCH_SHA,
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )
    loop.default_branch = "main"
    loop.dispatched_blocked_resumes = set()
    loop.dry_run = False
    messages: list[str] = []
    loop.log = messages.append  # type: ignore[method-assign]
    loop.check_state = lambda _head: "pending"  # type: ignore[method-assign]

    assert loop.perform_post_blocked_refresh_resume(
        state,
        [],
        [base_pass, gate],
        [prior_family, current_family],
        DEFAULT_BRANCH_SHA,
    ) is True
    assert messages == []

    loop.check_state = lambda _head: "success"  # type: ignore[method-assign]

    assert loop.perform_post_blocked_refresh_resume(
        state,
        [],
        [base_pass, gate],
        [prior_family, current_family],
        DEFAULT_BRANCH_SHA,
    ) is True
    assert github.workflow_calls == []
    assert messages == [
        f"waiting for dedicated design approval in phase-0b at {REFRESHED_HEAD_SHA[:12]}"
    ]


def blocked_run_loop(
    *, refresh_candidate: MarkerEvidence | None
) -> tuple[PhaseLoop, list[tuple[MarkerEvidence, str, str]]]:
    base_pass, gate = blocked_refresh_records()
    state = replace(
        blocked_phase_state(),
        labels=frozenset({"ai-loop", "ai-loop-blocked", "phase-0b"}),
    )
    requests: list[tuple[MarkerEvidence, str, str]] = []
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.dry_run = True
    loop.validate_local_checkout = lambda: None  # type: ignore[method-assign]
    loop.fail_if_expired = lambda: None  # type: ignore[method-assign]
    loop.current_default_branch_sha = (  # type: ignore[method-assign]
        lambda: DEFAULT_BRANCH_SHA
    )
    loop.pr_state = lambda: state  # type: ignore[method-assign]
    loop.comments = lambda: []  # type: ignore[method-assign]
    loop.trusted_markers = (  # type: ignore[method-assign]
        lambda _comments, name: [base_pass, gate]
        if name == "redteam-phase-gate"
        else []
    )
    loop.trusted_base_refresh_statuses = (  # type: ignore[method-assign]
        lambda _state, _records: []
    )
    loop.perform_base_refresh_label_transition = (  # type: ignore[method-assign]
        lambda _state, _records, _default: False
    )
    loop.perform_pending_base_refresh = (  # type: ignore[method-assign]
        lambda _state, _records, _default: False
    )
    loop.perform_post_blocked_refresh_resume = (  # type: ignore[method-assign]
        lambda _state, _requests, _phase_records, _family_records, _default: False
    )
    loop.base_refresh_candidate = (  # type: ignore[method-assign]
        lambda _state, _requests, _phase_records, _default: None
    )
    loop.blocked_base_refresh_candidate = (  # type: ignore[method-assign]
        lambda _state, _phase_records, _default: refresh_candidate
    )
    loop.request_base_refresh = (  # type: ignore[method-assign]
        lambda _state, record, *, target_base_sha, source_phase=None: requests.append(
            (record, target_base_sha, source_phase)
        )
    )
    loop.log = lambda _message: None  # type: ignore[method-assign]
    return loop, requests


def test_run_allows_trusted_blocked_limit_base_refresh_before_terminal_stop() -> None:
    _base_pass, gate = blocked_refresh_records()
    loop, requests = blocked_run_loop(refresh_candidate=gate)

    result = loop.run()

    assert result == "DRY_RUN:waiting for blocked current-Phase base refresh: phase-0b"
    assert requests == [(gate, DEFAULT_BRANCH_SHA, "phase-0c")]


def test_run_still_stops_blocked_phase_without_trusted_refresh() -> None:
    loop, requests = blocked_run_loop(refresh_candidate=None)

    with pytest.raises(LoopBlockedError, match="GitHub marked the loop blocked"):
        loop.run()

    assert requests == []


def base_refresh_record(
    *,
    head_sha: str = HEAD_SHA,
    target_base_sha: str = DEFAULT_BRANCH_SHA,
    prior_pass_reference: str = PHASE_RECORD_URL,
) -> MarkerEvidence:
    payload = base_refresh_payload()
    payload["head_sha"] = head_sha
    payload["target_base_sha"] = target_base_sha
    payload["prior_pass_reference"] = prior_pass_reference
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


def test_phase_zero_a_review_keeps_incorporated_base_when_default_branch_advanced() -> None:
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = _AncestorGitHub(  # type: ignore[assignment]
        {
            (HEAD_SHA, REFRESHED_HEAD_SHA),
            (DEFAULT_BRANCH_SHA, REFRESHED_HEAD_SHA),
        }
    )

    assert (
        loop.expected_base_sha(
            refreshed_phase_state(), [], [base_refresh_record()], "f" * 40
        )
        == DEFAULT_BRANCH_SHA
    )


def test_phase_zero_a_review_selects_unique_maximal_incorporated_refresh() -> None:
    later_head = "1" * 40
    later_base = "2" * 40
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = _AncestorGitHub(  # type: ignore[assignment]
        {
            (HEAD_SHA, REFRESHED_HEAD_SHA),
            (DEFAULT_BRANCH_SHA, REFRESHED_HEAD_SHA),
            (later_head, REFRESHED_HEAD_SHA),
            (later_base, REFRESHED_HEAD_SHA),
            (HEAD_SHA, later_head),
            (DEFAULT_BRANCH_SHA, later_base),
        }
    )
    refreshes = [
        base_refresh_record(
            head_sha=later_head,
            target_base_sha=later_base,
            prior_pass_reference=f"{PULL_REQUEST_PREFIX}#issuecomment-later-pass",
        ),
        base_refresh_record(),
    ]

    assert (
        loop.expected_base_sha(
            refreshed_phase_state(), [], refreshes, DEFAULT_BRANCH_SHA
        )
        == later_base
    )


def test_phase_zero_a_review_rejects_incomparable_incorporated_refreshes() -> None:
    other_head = "1" * 40
    other_base = "2" * 40
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = _AncestorGitHub(  # type: ignore[assignment]
        {
            (HEAD_SHA, REFRESHED_HEAD_SHA),
            (DEFAULT_BRANCH_SHA, REFRESHED_HEAD_SHA),
            (other_head, REFRESHED_HEAD_SHA),
            (other_base, REFRESHED_HEAD_SHA),
        }
    )
    refreshes = [
        base_refresh_record(),
        base_refresh_record(
            head_sha=other_head,
            target_base_sha=other_base,
            prior_pass_reference=f"{PULL_REQUEST_PREFIX}#issuecomment-other-pass",
        ),
    ]

    with pytest.raises(UntrustedEvidenceError, match="evidence is ambiguous"):
        loop.expected_base_sha(
            refreshed_phase_state(), [], refreshes, DEFAULT_BRANCH_SHA
        )


def test_initial_phase_zero_a_review_keeps_original_pr_base_sha() -> None:
    loop = PhaseLoop.__new__(PhaseLoop)

    assert loop.expected_base_sha(phase_state(), [], [], DEFAULT_BRANCH_SHA) == BASE_SHA


def prior_pass(head_sha: str) -> MarkerEvidence:
    payload = chained_phase_passes()[0].payload.copy()
    payload["reviewed_sha"] = head_sha
    return MarkerEvidence(
        payload,
        f"{PULL_REQUEST_PREFIX}#issuecomment-pass-{head_sha[:8]}",
        "github-actions[bot]",
        "",
    )


def later_phase_loop(ancestors: set[tuple[str, str]]) -> PhaseLoop:
    loop = PhaseLoop.__new__(PhaseLoop)
    github = _AncestorGitHub(ancestors)
    github.repository = "example/repo"  # type: ignore[attr-defined]
    loop.github = github  # type: ignore[assignment]
    loop.reviewer_login = REVIEWER_LOGIN
    loop.approver_login = ACTOR_LOGIN
    return loop


def test_later_phase_review_uses_unique_maximal_ancestor_pass() -> None:
    earlier = "1" * 40
    later = "2" * 40
    loop = later_phase_loop({(earlier, HEAD_SHA), (later, HEAD_SHA), (earlier, later)})

    assert (
        loop.expected_base_sha(
            phase_state(phase="phase-0b"),
            [prior_pass(later), prior_pass(earlier)],
            [],
            DEFAULT_BRANCH_SHA,
        )
        == later
    )


def test_later_phase_review_rejects_incomparable_prior_passes() -> None:
    first = "1" * 40
    second = "2" * 40
    loop = later_phase_loop({(first, HEAD_SHA), (second, HEAD_SHA)})

    with pytest.raises(UntrustedEvidenceError, match="PASS evidence.*ambiguous"):
        loop.expected_base_sha(
            phase_state(phase="phase-0b"),
            [prior_pass(first), prior_pass(second)],
            [],
            DEFAULT_BRANCH_SHA,
        )


def test_later_phase_review_rejects_unincorporated_prior_pass() -> None:
    loop = later_phase_loop(set())

    with pytest.raises(UntrustedEvidenceError, match="no trusted PASS"):
        loop.expected_base_sha(
            phase_state(phase="phase-0b"),
            [prior_pass("1" * 40)],
            [],
            DEFAULT_BRANCH_SHA,
        )


def test_later_phase_review_rejects_malformed_incorporated_prior_pass() -> None:
    pass_record = prior_pass("1" * 40)
    del pass_record.payload["loop_state"]
    loop = later_phase_loop({("1" * 40, HEAD_SHA)})

    with pytest.raises(UntrustedEvidenceError, match="missing or unknown fields"):
        loop.expected_base_sha(
            phase_state(phase="phase-0b"),
            [pass_record],
            [],
            DEFAULT_BRANCH_SHA,
        )


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


class _LabelsCommand:
    def __init__(self, labels: list[str]) -> None:
        self.arguments: list[str] = []
        self.labels = labels

    def run(self, arguments: list[str]) -> str:
        self.arguments = arguments
        return json.dumps([{"name": label} for label in self.labels])


class _MergeCommand:
    def __init__(self, response: str) -> None:
        self.arguments: list[str] = []
        self.response = response

    def run(self, arguments: list[str]) -> str:
        self.arguments = arguments
        return self.response


class _ClaimFailureCommand:
    def run(self, arguments: list[str]) -> str:
        raise PrerequisiteError("GitHub rejected or did not confirm the atomic ref creation")


def test_github_final_merge_uses_one_exact_head_request() -> None:
    client = GitHubClient.__new__(GitHubClient)
    client.repository = "example/repo"
    command = _MergeCommand(
        json.dumps({"sha": "9" * 40, "merged": True, "message": "merged"})
    )
    client.command = command  # type: ignore[assignment]

    result = client.merge_pull_request(3, "8" * 40, merge_method="merge")

    assert result == "9" * 40
    assert command.arguments == [
        "api",
        "--method",
        "PUT",
        "repos/example/repo/pulls/3/merge",
        "--raw-field",
        f"sha={'8' * 40}",
        "--raw-field",
        "merge_method=merge",
    ]


def test_github_final_merge_does_not_accept_an_uncertain_result() -> None:
    client = GitHubClient.__new__(GitHubClient)
    client.repository = "example/repo"
    client.command = _MergeCommand(  # type: ignore[assignment]
        json.dumps({"sha": None, "merged": False, "message": "conflict"})
    )

    with pytest.raises(FinalMergeRejectedError, match="did not confirm"):
        client.merge_pull_request(3, "8" * 40, merge_method="merge")


def test_github_final_merge_claim_is_an_atomic_exact_head_ref_creation() -> None:
    client = GitHubClient.__new__(GitHubClient)
    client.repository = "example/repo"
    claim_reference = f"refs/redteam-final-merge-attempts/pr-3-{'8' * 40}"
    command = _MergeCommand(
        json.dumps(
            {
                "ref": claim_reference,
                "object": {"type": "commit", "sha": "8" * 40},
            }
        )
    )
    client.command = command  # type: ignore[assignment]

    result = client.claim_final_merge_attempt(
        3,
        "8" * 40,
        claim_ref_prefix="refs/redteam-final-merge-attempts",
    )

    assert result == claim_reference
    assert command.arguments == [
        "api",
        "--method",
        "POST",
        "repos/example/repo/git/refs",
        "--raw-field",
        f"ref={claim_reference}",
        "--raw-field",
        f"sha={'8' * 40}",
    ]


def test_github_final_merge_claim_failure_requires_reconciliation() -> None:
    client = GitHubClient.__new__(GitHubClient)
    client.repository = "example/repo"
    client.command = _ClaimFailureCommand()  # type: ignore[assignment]

    with pytest.raises(FinalMergeReconciliationRequiredError, match="reconcile"):
        client.claim_final_merge_attempt(
            3,
            "8" * 40,
            claim_ref_prefix="refs/redteam-final-merge-attempts",
        )


def test_final_merge_attempt_rejects_claim_for_a_different_pr_head() -> None:
    with pytest.raises(UntrustedEvidenceError, match="exact PR and HEAD"):
        validate_final_merge_attempt_payload(
            {
                "schema_version": "1.0",
                "action": "ATTEMPT_FINAL_MERGE",
                "pull_request_number": 3,
                "head_sha": "8" * 40,
                "default_branch_sha": DEFAULT_BRANCH_SHA,
                "phase_gate_reference": PHASE_RECORD_URL,
                "policy_digest": "a" * 64,
                "attempted_by": ACTOR_LOGIN,
                "claim_reference": f"refs/redteam-final-merge-attempts/pr-30-{'8' * 40}",
            }
        )


class _FinalMergeGitHub:
    repository = "example/repo"

    def __init__(
        self,
        records: list[MarkerEvidence],
        *,
        default_is_ancestor: bool = True,
        merge_is_confirmed: bool = True,
    ) -> None:
        self.record = records[-1]
        self.default_is_ancestor = default_is_ancestor
        self.merge_is_confirmed = merge_is_confirmed
        self.merge_calls: list[tuple[int, str, str]] = []
        self.issue_comments: list[dict[str, object]] = []
        self.phase_comments: list[dict[str, object]] = [
            {
                "user": {"login": "github-actions[bot]"},
                "html_url": record.url,
                "body": marker("redteam-phase-gate", record.payload),
            }
            for record in records
        ]
        self.claims: set[str] = set()
        self.hidden_comment_calls: set[int] = set()
        self.comment_calls = 0

    def commit_statuses(self, sha: str) -> list[dict[str, object]]:
        assert sha == "8" * 40
        return [final_phase_status(self.record)]

    def check_runs(self, sha: str) -> list[dict[str, object]]:
        assert sha == "8" * 40
        return [
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in ("tests (3.12)", "tests (3.14)", "quality", "governance-integrity")
        ]

    def is_ancestor(self, ancestor_sha: str, descendant_sha: str) -> bool:
        assert ancestor_sha == DEFAULT_BRANCH_SHA
        assert descendant_sha == "8" * 40
        return self.default_is_ancestor

    def comments(self, number: int) -> list[dict[str, object]]:
        assert number == 3
        self.comment_calls += 1
        if self.comment_calls in self.hidden_comment_calls:
            return []
        return [*self.phase_comments, *self.issue_comments]

    def post_comment(self, number: int, body: str) -> dict[str, object]:
        assert number == 3
        comment: dict[str, object] = {
            "user": {"login": ACTOR_LOGIN},
            "html_url": f"{PULL_REQUEST_PREFIX}#issuecomment-final-attempt",
            "body": body,
        }
        self.issue_comments.append(comment)
        return comment

    def claim_final_merge_attempt(
        self,
        number: int,
        expected_head_sha: str,
        *,
        claim_ref_prefix: str,
    ) -> str:
        claim_reference = f"{claim_ref_prefix}/pr-{number}-{expected_head_sha}"
        if claim_reference in self.claims:
            raise FinalMergeReconciliationRequiredError(
                "atomic final-merge claim already exists; reconcile"
            )
        self.claims.add(claim_reference)
        return claim_reference

    def merge_pull_request(
        self, number: int, expected_head_sha: str, *, merge_method: str
    ) -> str:
        self.merge_calls.append((number, expected_head_sha, merge_method))
        if not self.merge_is_confirmed:
            raise FinalMergeRejectedError("GitHub did not confirm the merge")
        return "9" * 40


def final_merge_state(*, extra_labels: set[str] | None = None) -> PullRequestState:
    labels = {"ai-loop", "ai-project-complete", "ai-review-passed", "phase-5"}
    labels.update(extra_labels or set())
    return PullRequestState(
        number=3,
        head_sha="8" * 40,
        base_sha=BASE_SHA,
        base_ref="main",
        phase="phase-5",
        labels=frozenset(labels),
        state="open",
        head_repository="example/repo",
    )


def configured_final_merge_loop(
    state: PullRequestState, github: _FinalMergeGitHub
) -> PhaseLoop:
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = github  # type: ignore[assignment]
    loop.final_merge_policy = {
        "enabled": True,
        "merge_method": "merge",
        "claim_ref_prefix": "refs/redteam-final-merge-attempts",
        "required_phase": "phase-5",
        "required_labels": ["ai-loop", "ai-project-complete", "ai-review-passed", "phase-5"],
        "forbidden_labels": [
            "governance-change",
            "ai-human-gate",
            "ai-loop-blocked",
            "ai-needs-fix",
            "ai-needs-implementation",
            "ai-needs-review",
        ],
        "phase_status_context": "redteam/phase-review",
    }
    loop.reviewer_login = REVIEWER_LOGIN
    loop.approver_login = ACTOR_LOGIN
    loop.actor_login = ACTOR_LOGIN
    loop.pull_request_number = 3
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    loop.pr_state = lambda: state  # type: ignore[method-assign]
    loop.current_default_branch_sha = lambda: DEFAULT_BRANCH_SHA  # type: ignore[method-assign]
    return loop


def test_automatic_final_merge_revalidates_and_merges_exact_head_once() -> None:
    records = chained_phase_passes()
    state = final_merge_state()
    github = _FinalMergeGitHub(records)
    loop = configured_final_merge_loop(state, github)

    result = loop.automatic_final_merge(state, [], records, DEFAULT_BRANCH_SHA)

    assert result == f"PROJECT_MERGED:{'9' * 40}"
    assert github.merge_calls == [(3, "8" * 40, "merge")]
    assert len(github.issue_comments) == 1
    assert "redteam-final-merge-attempt" in str(github.issue_comments[0]["body"])
    assert len(github.claims) == 1


def test_automatic_final_merge_rejects_stop_label_without_calling_merge() -> None:
    records = chained_phase_passes()
    state = final_merge_state(extra_labels={"ai-loop-blocked"})
    github = _FinalMergeGitHub(records)
    loop = configured_final_merge_loop(state, github)

    with pytest.raises(UntrustedEvidenceError, match="stop-state label"):
        loop.automatic_final_merge(state, [], records, DEFAULT_BRANCH_SHA)

    assert github.merge_calls == []


def test_automatic_final_merge_rejects_governance_pr_without_calling_merge() -> None:
    records = chained_phase_passes()
    state = final_merge_state(extra_labels={"governance-change"})
    github = _FinalMergeGitHub(records)
    loop = configured_final_merge_loop(state, github)

    with pytest.raises(UntrustedEvidenceError, match="stop-state label"):
        loop.automatic_final_merge(state, [], records, DEFAULT_BRANCH_SHA)

    assert github.merge_calls == []


def test_automatic_final_merge_rejects_default_branch_not_in_head() -> None:
    records = chained_phase_passes()
    state = final_merge_state()
    github = _FinalMergeGitHub(records, default_is_ancestor=False)
    loop = configured_final_merge_loop(state, github)

    with pytest.raises(UntrustedEvidenceError, match="default branch in PR HEAD ancestry"):
        loop.automatic_final_merge(state, [], records, DEFAULT_BRANCH_SHA)

    assert github.merge_calls == []


def test_uncertain_final_merge_attempt_is_durable_and_never_retried() -> None:
    records = chained_phase_passes()
    state = final_merge_state()
    github = _FinalMergeGitHub(records, merge_is_confirmed=False)
    loop = configured_final_merge_loop(state, github)

    with pytest.raises(FinalMergeRejectedError, match="did not confirm"):
        loop.automatic_final_merge(state, [], records, DEFAULT_BRANCH_SHA)

    assert len(github.issue_comments) == 1
    assert github.merge_calls == [(3, "8" * 40, "merge")]

    with pytest.raises(FinalMergeReconciliationRequiredError, match="reconcile"):
        loop.automatic_final_merge(
            state,
            github.issue_comments,  # type: ignore[arg-type]
            records,
            DEFAULT_BRANCH_SHA,
        )

    assert github.merge_calls == [(3, "8" * 40, "merge")]


def test_concurrent_final_merge_runners_share_one_atomic_claim() -> None:
    records = chained_phase_passes()
    state = final_merge_state()
    github = _FinalMergeGitHub(records)
    # Both runners observed the same empty comment snapshot before either persisted
    # its audit comment; only the Git ref claim can serialize this interleaving.
    github.hidden_comment_calls = {1, 3}
    first_loop = configured_final_merge_loop(state, github)
    second_loop = configured_final_merge_loop(state, github)

    assert first_loop.automatic_final_merge(state, [], records, DEFAULT_BRANCH_SHA) == (
        f"PROJECT_MERGED:{'9' * 40}"
    )
    with pytest.raises(FinalMergeReconciliationRequiredError, match="reconcile"):
        second_loop.automatic_final_merge(state, [], records, DEFAULT_BRANCH_SHA)

    assert len(github.claims) == 1
    assert len(github.issue_comments) == 1
    assert github.merge_calls == [(3, "8" * 40, "merge")]


def test_post_claim_pr_drift_requires_reconciliation_without_merge() -> None:
    records = chained_phase_passes()
    state = final_merge_state()
    changed_state = final_merge_state(extra_labels={"ai-loop-blocked"})
    github = _FinalMergeGitHub(records)
    loop = configured_final_merge_loop(state, github)
    observed_states = iter((state, changed_state))
    loop.pr_state = lambda: next(observed_states)  # type: ignore[method-assign]

    with pytest.raises(FinalMergeReconciliationRequiredError, match="reconcile"):
        loop.automatic_final_merge(state, [], records, DEFAULT_BRANCH_SHA)

    assert len(github.claims) == 1
    assert len(github.issue_comments) == 1
    assert github.merge_calls == []


def test_post_claim_default_branch_drift_requires_reconciliation_without_merge() -> None:
    records = chained_phase_passes()
    state = final_merge_state()
    github = _FinalMergeGitHub(records)
    loop = configured_final_merge_loop(state, github)
    observed_defaults = iter((DEFAULT_BRANCH_SHA, "e" * 40))
    loop.current_default_branch_sha = lambda: next(  # type: ignore[method-assign]
        observed_defaults
    )

    with pytest.raises(FinalMergeReconciliationRequiredError, match="reconcile"):
        loop.automatic_final_merge(state, [], records, DEFAULT_BRANCH_SHA)

    assert len(github.claims) == 1
    assert len(github.issue_comments) == 1
    assert github.merge_calls == []


def test_post_claim_check_drift_requires_reconciliation_without_merge() -> None:
    records = chained_phase_passes()
    state = final_merge_state()
    github = _FinalMergeGitHub(records)
    loop = configured_final_merge_loop(state, github)
    observed_checks = iter(("success", "failure"))
    loop.check_state = lambda _sha: next(observed_checks)  # type: ignore[method-assign]

    with pytest.raises(FinalMergeReconciliationRequiredError, match="reconcile"):
        loop.automatic_final_merge(state, [], records, DEFAULT_BRANCH_SHA)

    assert len(github.claims) == 1
    assert len(github.issue_comments) == 1
    assert github.merge_calls == []


def test_post_claim_status_drift_requires_reconciliation_without_merge() -> None:
    records = chained_phase_passes()
    state = final_merge_state()
    github = _FinalMergeGitHub(records)
    passing_status = final_phase_status(records[-1])
    failing_status = {**passing_status, "state": "failure"}
    observed_statuses = iter(([passing_status], [failing_status]))
    github.commit_statuses = lambda _sha: next(  # type: ignore[method-assign]
        observed_statuses
    )
    loop = configured_final_merge_loop(state, github)

    with pytest.raises(FinalMergeReconciliationRequiredError, match="reconcile"):
        loop.automatic_final_merge(state, [], records, DEFAULT_BRANCH_SHA)

    assert len(github.claims) == 1
    assert len(github.issue_comments) == 1
    assert github.merge_calls == []


def test_post_claim_earlier_phase_record_drift_requires_reconciliation() -> None:
    records = chained_phase_passes()
    state = final_merge_state()
    github = _FinalMergeGitHub(records)
    loop = configured_final_merge_loop(state, github)
    original_post_comment = github.post_comment

    def post_comment_and_replace_phase_0a(
        number: int, body: str
    ) -> dict[str, object]:
        result = original_post_comment(number, body)
        replacement = {**records[0].payload, "summary": "replacement valid Phase 0A PASS"}
        github.phase_comments[0]["body"] = marker("redteam-phase-gate", replacement)
        return result

    github.post_comment = post_comment_and_replace_phase_0a  # type: ignore[method-assign]

    with pytest.raises(FinalMergeReconciliationRequiredError, match="reconcile"):
        loop.automatic_final_merge(state, [], records, DEFAULT_BRANCH_SHA)

    assert len(github.claims) == 1
    assert len(github.issue_comments) == 1
    assert github.merge_calls == []

class _ComparisonGitHub:
    is_ancestor = GitHubClient.is_ancestor

    def __init__(self, comparison: dict[str, object]) -> None:
        self.comparison = comparison
        self.calls = 0

    def compare(self, base_sha: str, head_sha: str) -> dict[str, object]:
        self.calls += 1
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


def test_ancestor_check_caches_immutable_comparison_results() -> None:
    github = _ComparisonGitHub(
        {
            "merge_base_commit": {"sha": HEAD_SHA},
            "behind_by": 0,
            "status": "ahead",
        }
    )

    assert github.is_ancestor(HEAD_SHA, REFRESHED_HEAD_SHA) is True
    assert github.is_ancestor(HEAD_SHA, REFRESHED_HEAD_SHA) is True
    assert github.calls == 1


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


def test_local_base_refresh_label_transition_sets_one_exact_label_set() -> None:
    client = GitHubClient.__new__(GitHubClient)
    client.repository = "example/repo"
    labels = frozenset({"ai-loop", "ai-needs-implementation", "phase-0a"})
    command = _LabelsCommand(sorted(labels))
    client.command = command  # type: ignore[assignment]

    assert client.set_pull_request_labels(3, labels) == labels
    assert command.arguments == [
        "api",
        "--method",
        "PUT",
        "repos/example/repo/issues/3/labels",
        "--raw-field",
        "labels[]=ai-loop",
        "--raw-field",
        "labels[]=ai-needs-implementation",
        "--raw-field",
        "labels[]=phase-0a",
    ]
    assert "/merge" not in " ".join(command.arguments)
