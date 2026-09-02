from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from automation.run_phase_loop import (
    INVARIANT_FAMILIES,
    base_refresh_checkpoint_payload,
    canonical_digest,
)
from scripts.ci.validate_automation import (
    AutomationValidationError,
    strict_json_load,
    validate_automation,
)
from scripts.ci.validate_invariant_audit import (
    InvariantAuditError,
    validate_invariant_audit,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_repository_automation_configuration_is_valid() -> None:
    validate_automation(REPO_ROOT)


def test_runtime_family_ids_match_machine_policy() -> None:
    policy = json.loads(
        (REPO_ROOT / "automation" / "invariant-families.json").read_text(encoding="utf-8")
    )

    assert tuple(item["id"] for item in policy["families"]) == INVARIANT_FAMILIES


def test_review_prompt_defines_invariant_audit_transition_bindings() -> None:
    prompt = (REPO_ROOT / "automation" / "chatgpt-event-task-prompt.md").read_text(
        encoding="utf-8"
    )

    assert "`audit.request.head_sha` is the full input HEAD" in prompt
    assert "ready marker's `head_sha` is the full output HEAD" in prompt
    assert "not a hash of the file's raw bytes" in prompt


def _audit_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "audit-repo"
    shutil.copytree(REPO_ROOT / "automation", repo / "automation")
    (repo / "docs" / "review").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_family.py").write_text("def test_family():\n    pass\n")
    git = shutil.which("git")
    assert git is not None

    def run_git(*arguments: str, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed test-only git executable and arguments.
            [git, *arguments],
            cwd=repo,
            check=True,
            capture_output=capture_output,
            text=True,
        )

    run_git("init", "-q")
    run_git("config", "user.email", "audit@example.invalid")
    run_git("config", "user.name", "Audit Test")
    run_git("add", ".")
    run_git("commit", "-qm", "audit base")
    head = run_git("rev-parse", "HEAD", capture_output=True).stdout.strip()
    policy = json.loads((repo / "automation" / "invariant-families.json").read_text())
    report = {
        "schema_version": "1.0",
        "phase": "phase-0c",
        "request": {
            "head_sha": head,
            "reference": "https://github.com/example/repo/pull/1#issuecomment-1",
            "action": "IMPLEMENT_PHASE",
        },
        "families": [
            {
                "id": family,
                "status": "verified-unchanged",
                "entry_points": ["tests/test_family.py"],
                "sibling_paths": ["tests/test_family.py"],
                "invariant_evidence": ["Inspected the complete test boundary."],
                "tests": ["tests/test_family.py"],
                "test_modes": ["positive", "negative", "failure"],
            }
            for family in policy["phases"]["phase-0c"]
        ],
        "cross_family_tests": ["tests/test_family.py"],
        "notes": "No production changes in the validation fixture.",
    }
    report_path = repo / "docs" / "review" / "phase-0c-invariant-audit.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return repo, report_path


def test_complete_invariant_family_audit_is_valid(tmp_path: Path) -> None:
    repo, _ = _audit_repo(tmp_path)

    digest = validate_invariant_audit(repo, "phase-0c")

    assert digest is not None and len(digest) == 64


def test_invariant_family_audit_rejects_missing_family(tmp_path: Path) -> None:
    repo, report_path = _audit_repo(tmp_path)
    report = json.loads(report_path.read_text())
    report["families"].pop()
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(InvariantAuditError, match="exact required family set"):
        validate_invariant_audit(repo, "phase-0c")


def test_affected_stateful_family_requires_model_based_test(tmp_path: Path) -> None:
    repo, report_path = _audit_repo(tmp_path)
    report = json.loads(report_path.read_text())
    report["families"][0]["status"] = "affected"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(InvariantAuditError, match="property/state-machine"):
        validate_invariant_audit(repo, "phase-0c")


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


def test_unknown_final_merge_policy_field_is_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "automation", repo / "automation")
    shutil.copytree(REPO_ROOT / "prompts", repo / "prompts")
    policy_path = repo / "automation" / "final-merge-policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["bypass_checks"] = True
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(AutomationValidationError, match="schema validation failed"):
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
        "Exhaustive Codex findings must be retained in one formal review",
        "finding_count: currentFindings.length",
        "findings: currentFindings.map",
        "finding_reference: item.html_url",
        "all ${currentFindings.length} retained P0/P1 finding(s)",
        "invariant_family: invariantFamily(item.body)",
        "redteam-invariant-family-review",
        "recurringFamilies.length > 0",
        "record.stop_reason = 'INVARIANT_FAMILY_RECURRENCE'",
        "record.recurring_families = [...recurringFamilies].sort()",
        "record.finding_references = currentFindings",
        "semantic invariant family recurred",
        "sameFindingCount + 1 >= 5",
        "AI_LOOP_MAX_ITERATIONS must be exactly 5",
        "parseTime(item.created_at, 'Codex finding') <= triggerTime) return false",
        "duplicate JSON key",
        "redteam/base-refresh/",
        "listCommitStatusesForRef",
        "ref: pass.reviewed_sha",
        "status.target_url !== pass._comment_url",
        "target_base_sha",
        "comparison.data.merge_base_commit?.sha === ancestorSha",
        "isAncestor(refresh.target_base_sha, reviewedSha)",
        "Reviewed Phase 0A head is not descended from a trusted base refresh",
        "Incorporated Phase 0A base-refresh evidence is ambiguous",
        "maximalRefreshes.length !== 1",
        "incorporatedPassHeads",
        "maximalPassHeads.length !== 1",
        "Incorporated PASS evidence for previous phase",
        "Pull request head or phase changed before recording the gate",
        "phase_transition",
        "automation/transition_phase.py",
    ):
        assert required_control in workflow
    assert "liveDefaultCommit.sha !== refreshTargetSha" not in workflow
    assert "Default branch changed before recording the refreshed Phase 0A gate" not in workflow
    assert "status.sha !== pass.reviewed_sha" not in workflow
    assert "previousPasses.at(-1).reviewed_sha" not in workflow
    assert "await removeLabel(phase)" not in workflow
    assert "await addLabels([next.label, 'ai-needs-implementation'])" not in workflow
    assert "Review evidence must contain exactly one redteam-ai-review marker" not in workflow
    assert "Current-head Codex finding predates the trusted trigger" not in workflow
    assert "sameFindingCount + 1 >= 3" not in workflow


def test_ci_binds_pre_review_audit_to_request_and_output_head() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    phase_gate = (REPO_ROOT / "scripts" / "ci" / "run_phase_gate.sh").read_text(
        encoding="utf-8"
    )

    for required_control in (
        "auditData.request?.head_sha",
        "auditData.request?.action",
        "auditData.request?.reference",
        "redteam-invariant-audit",
        "audit_digest",
        "context.payload.before",
    ):
        assert required_control in workflow
    assert "validate_invariant_audit.py --phase" in phase_gate


def test_ci_and_review_retry_limits_are_exactly_five() -> None:
    for relative_path in (
        ".github/workflows/ci.yml",
        ".github/workflows/ai-loop-control.yml",
    ):
        workflow = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        assert "if (maximum !== 5)" in workflow
        assert "AI_LOOP_MAX_ITERATIONS must be exactly 5" in workflow
        assert "maximum < 1" not in workflow
        assert "maximum > 20" not in workflow


def test_phase_gate_uses_the_marker_transition_protocol() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "ai-loop-control.yml").read_text(
        encoding="utf-8"
    )
    helper = (REPO_ROOT / "automation" / "transition_phase.py").read_text(
        encoding="utf-8"
    )

    assert "issues.setLabels" not in workflow
    assert "issues.setLabels" not in helper
    assert 'TRANSITION_MARKER = "ai-review-passed"' in helper
    add_next = helper.index("client.add_label(request, request.next_phase)")
    remove_current = helper.index("client.remove_label(request, request.current_phase)")
    add_implementation = helper.index("client.add_label(request, IMPLEMENTATION_LABEL)")
    create_request = helper.index("    client.create_request_comment(request)")
    remove_marker = helper.index("client.remove_label(request, TRANSITION_MARKER)")
    assert add_next < remove_current < add_implementation < create_request < remove_marker
    assert "released_labels = _label_names" in helper
    assert '"PUT"' not in helper


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


def test_resume_workflow_can_comment_on_pr_without_merge_authority() -> None:
    workflow = (
        REPO_ROOT / ".github" / "workflows" / "resume-ai-loop.yml"
    ).read_text(encoding="utf-8")
    permissions = workflow.split("\npermissions:\n", maxsplit=1)[1].split(
        "\njobs:\n", maxsplit=1
    )[0]

    assert permissions.strip().splitlines() == [
        "contents: read",
        "  issues: write",
        "  pull-requests: write",
        "  statuses: write",
    ]
    assert "github.rest.issues.createComment" in workflow
    assert "verifyAppliedCheckpoint" in workflow
    assert "resolutionReference" in workflow
    assert "maximalGates" not in workflow
    assert "const ancestryCache = new Map()" in workflow
    assert "A current-HEAD Phase Gate supersedes" in workflow
    for forbidden_operation in (
        "github.rest.pulls.merge",
        "mergePullRequest",
        "/pulls/{number}/merge",
    ):
        assert forbidden_operation not in workflow


def test_design_resume_is_dedicated_single_use_and_fail_closed() -> None:
    workflow = (
        REPO_ROOT / ".github" / "workflows" / "approve-ai-loop-design-resume.yml"
    ).read_text(encoding="utf-8")
    helper_path = REPO_ROOT / "automation" / "approve_design_resume.js"
    helper = helper_path.read_text(encoding="utf-8")
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
    for required_control in (
        "APPROVE_DESIGN_RESUME",
        "blocked_gate_reference",
        "design_commit_sha",
        "design_reference",
        "redteam-design-approval",
        "RESUME_AFTER_DESIGN_APPROVAL",
        "policy_digest",
        "INVARIANT_FAMILY_RECURRENCE",
        "Required current-HEAD check is not uniquely successful",
        "Design approval consumption is missing or ambiguous",
        "Approved design commit is not incorporated in main and current PR HEAD",
        "Design Resume workflow code is not the current default-branch revision",
        "issues.setLabels",
    ):
        assert required_control in workflow or required_control in helper
    assert "contents: write" not in workflow
    assert "secrets." not in workflow
    for forbidden_operation in (
        "github.rest.pulls.merge",
        "mergePullRequest",
        "/pulls/{number}/merge",
        "updateBranch",
    ):
        assert forbidden_operation not in workflow
        assert forbidden_operation not in helper

    node = shutil.which("node")
    assert node is not None
    parser_test = """
const helper = require(process.argv[1]);
let rejected = false;
try {
  helper.strictJsonParse('{"outer":{"phase":"phase-0c","phase":"phase-1"}}');
} catch (error) {
  rejected = String(error).includes('duplicate JSON key');
}
if (!rejected) process.exit(1);
"""
    subprocess.run(  # noqa: S603 - fixed node executable and test-only source.
        [node, "-e", parser_test, str(helper_path)],
        cwd=REPO_ROOT,
        check=True,
    )
    digest_test = """
const fs = require('fs');
const helper = require(process.argv[1]);
const policy = helper.strictJsonParse(fs.readFileSync(process.argv[2], 'utf8'));
process.stdout.write(helper.canonicalDigest(policy));
"""
    node_digest = subprocess.run(  # noqa: S603 - fixed node executable and test-only source.
        [
            node,
            "-e",
            digest_test,
            str(helper_path),
            str(REPO_ROOT / "automation" / "invariant-families.json"),
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    policy = json.loads(
        (REPO_ROOT / "automation" / "invariant-families.json").read_text(
            encoding="utf-8"
        )
    )
    assert node_digest == canonical_digest(policy)


def test_loop_control_projection_policy_is_shared_and_block_safe() -> None:
    helper_path = REPO_ROOT / "automation" / "loop_control_state.js"
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    approval = (REPO_ROOT / "automation" / "approve_design_resume.js").read_text(
        encoding="utf-8"
    )

    assert "loop_control_state.js" in workflow
    assert "shouldPublishReviewReady" in workflow
    assert "Blocked PR passed deterministic checks" in workflow
    assert "loop_control_state" in approval
    assert "assertDesignApprovalProjection" in approval

    node = shutil.which("node")
    assert node is not None
    policy_test = """
const control = require(process.argv[1]);
const blocked = ['ai-loop', 'phase-0c', 'ai-loop-blocked'];
if (control.shouldPublishReviewReady(blocked)) process.exit(1);
control.assertDesignApprovalProjection(
  [...blocked, 'ai-needs-review'], 'phase-0c', true
);
let rejected = false;
try {
  control.assertDesignApprovalProjection(
    [...blocked, 'ai-needs-implementation'], 'phase-0c', true
  );
} catch (_) {
  rejected = true;
}
if (!rejected) process.exit(1);
"""
    subprocess.run(  # noqa: S603 - fixed node executable and test-only source.
        [node, "-e", policy_test, str(helper_path)],
        cwd=REPO_ROOT,
        check=True,
    )


def test_blocked_base_refresh_uses_one_current_head_checkpoint() -> None:
    helper_path = REPO_ROOT / "automation" / "base_refresh_checkpoint.js"
    workflow = (
        REPO_ROOT / ".github" / "workflows" / "refresh-ai-loop-base.yml"
    ).read_text(encoding="utf-8")
    assert "base_refresh_checkpoint.js" in workflow
    assert "verifyAppliedCheckpoint" in workflow
    assert "ready.head_sha !== authorization.reviewed_sha" in workflow
    assert "/^[0-9a-f]{40}$/.test(authorization.reviewed_sha)" in workflow
    assert "Non-design blocked Gate cannot cross" not in workflow
    assert "verifyPreparedRefreshEdge" in workflow
    assert "BASE_REFRESH_APPLIED" in helper_path.read_text(encoding="utf-8")
    for required_control in (
        "AI_GATE_APPROVER_LOGIN",
        "context.actor",
        "pr.head.sha !== expectedHeadSha",
        "defaultCommit.sha !== context.sha",
        "ai-loop-blocked",
        "contains a duplicate JSON key",
        "authorization.reviewed_sha !== previousHeadSha",
        "verifyAppliedCheckpoint",
        "Pull request changed before checkpoint publication",
        "createCommitStatus",
    ):
        assert required_control in workflow
    permissions = workflow.split("\npermissions:\n", maxsplit=1)[1].split(
        "\njobs:\n", maxsplit=1
    )[0]
    assert permissions.strip().splitlines() == [
        "contents: read",
        "  pull-requests: read",
        "  statuses: write",
    ]
    for forbidden_operation in (
        "github.rest.pulls.merge",
        "updateBranch",
        "contents: write",
        "pull-requests: write",
    ):
        assert forbidden_operation not in workflow

    node = shutil.which("node")
    assert node is not None
    policy_test = """
const control = require(process.argv[1]);
const previous = 'a'.repeat(40);
const current = 'b'.repeat(40);
const currentBase = 'c'.repeat(40);
const gateReference = 'https://github.com/example/repo/pull/3#issuecomment-gate';
const authorization = {
  context: `redteam/base-refresh/phase-0c/phase-0b/${currentBase}`,
  state: 'success',
  description: control.AUTHORIZATION_STATUS_DESCRIPTION,
  target_url: gateReference,
  creator: {login: 'github-actions[bot]'},
};
const payload = control.checkpointPayload({
  headSha: current, previousHeadSha: previous, targetBaseSha: currentBase,
  sourcePhase: 'phase-0c', revalidationPhase: 'phase-0b',
  authorizationReference: gateReference,
});
const applied = {
  context: `${control.CHECKPOINT_STATUS_PREFIX}${control.checkpointDigest(payload)}`,
  state: 'success', description: control.CHECKPOINT_STATUS_DESCRIPTION,
  target_url: gateReference, creator: {login: 'github-actions[bot]'},
};
const commits = {[current]: {
  sha: current, parents: [{sha: previous}, {sha: currentBase}],
}};
const statuses = {[previous]: [authorization], [current]: [applied]};
const github = {
  rest: {
    git: {getCommit: async ({commit_sha}) => ({data: commits[commit_sha]})},
    repos: {listCommitStatusesForRef: () => null},
  },
  paginate: async (_method, {ref}) => statuses[ref] || [],
};
(async () => {
  await control.verifyPreparedRefreshEdge({
    github, owner: 'example', repo: 'repo', headSha: current,
    previousHeadSha: previous, targetBaseSha: currentBase,
    authorizationReference: gateReference, sourcePhase: 'phase-0c',
    revalidationPhase: 'phase-0b',
  });
  await control.verifyAppliedCheckpoint({
    github, owner: 'example', repo: 'repo', headSha: current,
    authorizationReference: gateReference, sourcePhase: 'phase-0c',
    revalidationPhase: 'phase-0b',
  });
  applied.context = `${control.CHECKPOINT_STATUS_PREFIX}${'0'.repeat(64)}`;
  let rejected = false;
  try {
    await control.verifyAppliedCheckpoint({
      github, owner: 'example', repo: 'repo', headSha: current,
      authorizationReference: gateReference, sourcePhase: 'phase-0c',
      revalidationPhase: 'phase-0b',
    });
  } catch (_) {
    rejected = true;
  }
  if (!rejected) process.exit(1);
})().catch(() => process.exit(1));
"""
    subprocess.run(  # noqa: S603 - fixed node executable and test-only source.
        [node, "-e", policy_test, str(helper_path)],
        cwd=REPO_ROOT,
        check=True,
    )


def test_checkpoint_digest_is_identical_in_python_and_workflow_javascript() -> None:
    helper_path = REPO_ROOT / "automation" / "base_refresh_checkpoint.js"
    payload = base_refresh_checkpoint_payload(
        head_sha="b" * 40,
        previous_head_sha="a" * 40,
        target_base_sha="c" * 40,
        source_phase="phase-0c",
        revalidation_phase="phase-0b",
        authorization_reference=(
            "https://github.com/example/repo/pull/3#issuecomment-gate"
        ),
    )
    node = shutil.which("node")
    assert node is not None
    script = """
const control = require(process.argv[1]);
const payload = JSON.parse(process.argv[2]);
process.stdout.write(control.checkpointDigest(payload));
"""
    result = subprocess.run(  # noqa: S603 - fixed node executable and test-only source.
        [node, "-e", script, str(helper_path), json.dumps(payload)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout == canonical_digest(payload)


def test_generic_resume_and_recovery_reject_design_stop() -> None:
    resume = (
        REPO_ROOT / ".github" / "workflows" / "resume-ai-loop.yml"
    ).read_text(encoding="utf-8")
    recovery = (
        REPO_ROOT / ".github" / "workflows" / "revalidate-blocked-phase.yml"
    ).read_text(encoding="utf-8")

    assert "DESIGN_CHANGE_REQUIRED rejects generic Resume AI Loop" in resume
    assert (
        "DESIGN_CHANGE_REQUIRED cannot use Recover Blocked AI Loop Current Phase"
        in recovery
    )
    assert "redteam-invariant-family-review" in resume
    assert "redteam-invariant-family-review" in recovery


def test_current_phase_recovery_is_identical_tree_and_fail_closed() -> None:
    workflow = (
        REPO_ROOT / ".github" / "workflows" / "revalidate-blocked-phase.yml"
    ).read_text(encoding="utf-8")
    assert "\npermissions: {}\n" in workflow
    assert """  validate:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      checks: read
      contents: read
      pull-requests: read
""" in workflow
    assert """  publish:
    needs: validate
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      checks: read
      contents: read
      issues: write
      pull-requests: write
      statuses: write
""" in workflow
    for required_control in (
        "RECOVER_CURRENT_PHASE",
        "AI_GATE_APPROVER_LOGIN",
        "AI_REVIEWER_LOGIN",
        "reviewed_head_sha",
        "reviewedCommit.commit.tree.sha !== currentCommit.commit.tree.sha",
        "isAncestor(reviewedHead, currentHead)",
        "original_commit_id !== reviewedHead",
        "review.commit_id !== reviewedHead",
        "Exactly one trusted current-phase CHANGES_REQUESTED gate is required",
        "Current-phase gate is not bound to one incorporated adjacent PASS",
        "Required current-head check is not uniquely successful",
        "Repository or PR state changed during current-phase validation",
        'run: bash scripts/ci/run_phase_gate.sh "$SOURCE_PHASE"',
        "redteam-implementation-request",
        "redteam-ready-for-review",
        "github.rest.issues.setLabels",
        "AUTHORIZED_EVIDENCE_DIGEST",
        "AUTHORIZED_LABELS_DIGEST",
        "PR changed during the exact current-phase label transition",
    ):
        assert required_control in workflow
    read_only_job = workflow.split("\n  publish:\n", maxsplit=1)[0]
    assert "issues: write" not in read_only_job
    assert "pull-requests: write" not in read_only_job
    assert "statuses: write" not in read_only_job
    assert "sourceIndex < 1 || sourceIndex > 5" in workflow
    assert "contents: write" not in workflow
    assert "secrets." not in workflow
    for forbidden_operation in (
        "github.rest.pulls.merge",
        "mergePullRequest",
        "updateBranch",
        "/pulls/{number}/merge",
    ):
        assert forbidden_operation not in workflow


def test_documented_reviewer_login_includes_bot_suffix() -> None:
    runbook = (REPO_ROOT / "docs" / "ai-loop-runbook.md").read_text(encoding="utf-8")

    assert "AI_REVIEWER_LOGIN --body 'chatgpt-codex-connector[bot]'" in runbook


def test_base_refresh_is_sha_bound_and_separate_from_exact_sha_final_merge() -> None:
    workflow = (
        REPO_ROOT / ".github" / "workflows" / "refresh-ai-loop-base.yml"
    ).read_text(encoding="utf-8")
    runner = (REPO_ROOT / "automation" / "run_phase_loop.py").read_text(encoding="utf-8")

    for required_control in (
        "REFRESH_AI_LOOP_BASE",
        "AI_GATE_APPROVER_LOGIN",
        "AI_REVIEWER_LOGIN",
        "source_phase",
        "expected_head_sha",
        "target_base_sha",
        "prior_pass_reference",
        "redteam/base-refresh/",
        "set_pull_request_labels",
        "createCommitStatus",
        "listCommitStatusesForRef",
        "trusted exact-SHA base refresh authorization",
        "contains a duplicate JSON key",
        "Reauthorization requires a trusted prior base-refresh status",
        "isBlockedCurrentPhase",
        "Blocked current Phase lacks one trusted adjacent base PASS",
        "Blocked current-Phase base PASS is not incorporated in HEAD",
        "authorization.ready_reference",
        "redteam-ready-for-review",
        "Blocked current Phase lacks trusted exact-HEAD ready evidence",
        "if (isBlockedCurrentPhase)",
        "item.user?.login === 'github-actions[bot]'",
        "blocked_base_refresh_candidate",
        "perform_post_blocked_refresh_resume",
        "resuming {state.phase} after trusted current-Phase base refresh",
    ):
        assert required_control in workflow or required_control in runner
    permissions = workflow.split("\npermissions:\n", maxsplit=1)[1].split(
        "\njobs:\n", maxsplit=1
    )[0]
    assert permissions.strip().splitlines() == [
        "contents: read",
        "  pull-requests: read",
        "  statuses: write",
    ]
    assert r"while (/\s/.test" in workflow
    assert r"while (/\\s/.test" not in workflow
    assert r"!/[\s,}\]]/.test" in workflow
    assert "pr.base.sha !== targetBaseSha" not in workflow
    assert "contents: write" not in workflow
    assert "pull-requests: write" not in workflow
    assert "github.rest.issues.setLabels" not in workflow
    assert "github.rest.issues.createComment" not in workflow
    assert "secrets." not in workflow
    assert "update-branch" in runner
    for forbidden_operation in (
        "github.rest.pulls.merge",
        "mergePullRequest",
        "/pulls/{number}/merge",
        "/pulls/3/merge",
    ):
        assert forbidden_operation not in workflow
    assert "merge_pull_request" in runner
    assert 'f"sha={expected_head_sha}"' in runner
    assert runner.count('f"repos/{self.repository}/pulls/{number}/merge"') == 1


def test_final_merge_policy_is_fail_closed_and_local_only() -> None:
    policy = json.loads(
        (REPO_ROOT / "automation" / "final-merge-policy.json").read_text(encoding="utf-8")
    )
    runner = (REPO_ROOT / "automation" / "run_phase_loop.py").read_text(encoding="utf-8")

    assert policy["enabled"] is True
    assert policy["required_phase"] == "phase-5"
    assert policy["merge_method"] == "merge"
    assert policy["required_labels"] == [
        "ai-loop",
        "ai-project-complete",
        "ai-review-passed",
        "phase-5",
    ]
    assert "governance-change" in policy["forbidden_labels"]
    assert "validate_final_merge_phase_chain" in runner
    assert "validate_final_phase_status" in runner
    assert "redteam-final-merge-attempt" in runner
    assert "FinalMergeReconciliationRequiredError" in runner
    assert policy["claim_ref_prefix"] == "refs/redteam-final-merge-attempts"
    assert "claim_final_merge_attempt" in runner
    assert "current default branch in PR HEAD ancestry" in runner
    assert "PROJECT_MERGED" in runner
    assert runner.index("redteam-final-merge-attempt") < runner.index(
        "self.github.merge_pull_request("
    )
    merge_gate = runner[runner.index("    def automatic_final_merge(") :]
    assert merge_gate.index("self.github.claim_final_merge_attempt(") < merge_gate.index(
        "self.github.post_comment("
    ) < merge_gate.index("self.github.merge_pull_request(")
    assert merge_gate.rindex("validate_final_phase_status(") < merge_gate.index(
        "self.github.merge_pull_request("
    )
    assert merge_gate.count("validated_final_merge_phase_chain(") == 2
    assert "final_merge_phase_chain_identity(claimed_phase_chain)" in merge_gate
    for workflow_path in (REPO_ROOT / ".github" / "workflows").glob("*.yml"):
        workflow = workflow_path.read_text(encoding="utf-8")
        assert "github.rest.pulls.merge" not in workflow
        assert "/pulls/{number}/merge" not in workflow
