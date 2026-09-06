from __future__ import annotations

import copy
import io
import json
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from automation import local_execution as local
from automation.local_worker import LocalValidationResult, LocalWorkerResult
from automation.run_phase_loop import (
    REQUIRED_CHECK_ORDER,
    MarkerEvidence,
    PhaseLoop,
    PrerequisiteError,
    canonical_digest,
)

ROOT = Path(__file__).resolve().parents[2]
SESSION = "0199a213-81c0-7800-8aa1-bbab2a035a53"


class GitHubDouble:
    repository = "example/repo"

    def __init__(self, root: Path, sha: str) -> None:
        self.root = root
        self.head = self.base = sha
        self.items: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.claims: set[str] = set()
        self.labels = {"ai-loop", "phase-0a", "ai-needs-implementation"}
        self.check_status = "success"
        self.calls: list[list[str]] = []
        self.command = self
        self.clock = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=60)
        self.fail_claim = self.fail_post = False

    def tick(self) -> str:
        self.clock += timedelta(seconds=1)
        return self.now()

    def now(self) -> str:
        return self.clock.isoformat(timespec="seconds").replace("+00:00", "Z")

    def run(self, arguments: list[str]) -> str:
        self.calls.append(arguments)
        assert arguments[:3] == ["api", "--method", "POST"]
        assert arguments[3] == "repos/example/repo/git/refs"
        reference = next(value[4:] for value in arguments if value.startswith("ref="))
        if reference in self.claims:
            raise PrerequisiteError("already exists")
        self.claims.add(reference)
        if self.fail_claim:
            raise PrerequisiteError("response lost after write")
        return json.dumps({"ref": reference, "object": {"sha": self.head, "type": "commit"}})

    def post_comment(self, number: int, body: str) -> dict[str, Any]:
        assert number == 3
        at = self.tick()
        item = {"html_url": f"https://github.com/example/repo/pull/3#issuecomment-{len(self.items)+1}",
                "user": {"login": "operator"}, "body": body,
                "created_at": at, "updated_at": at}
        self.items.append(item)
        if self.fail_post:
            raise PrerequisiteError("response lost after write")
        return copy.deepcopy(item)

    def comments(self, number: int) -> list[dict[str, Any]]:
        assert number == 3
        return copy.deepcopy(self.items)

    def timeline(self, number: int) -> list[dict[str, Any]]:
        assert number == 3
        return copy.deepcopy(self.events)

    def commit_statuses(self, _sha: str) -> list[dict[str, Any]]:
        return []

    def check_runs(self, _sha: str) -> list[dict[str, Any]]:
        return [{"name": name, "status": "completed", "conclusion": self.check_status}
                for name in REQUIRED_CHECK_ORDER]

    def default_branch_sha(self, _branch: str) -> str:
        return self.base

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        return ancestor == descendant or ancestor == self.base

    def pull_request(self, number: int) -> dict[str, Any]:
        assert number == 3
        return {"head": {"sha": self.head, "ref": "ai/fixture",
                         "repo": {"full_name": self.repository}},
                "base": {"sha": self.base, "ref": "main"}, "state": "open",
                "labels": [{"name": name} for name in sorted(self.labels)]}


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[local.LocalExecution,
                                                                  PhaseLoop, GitHubDouble]:
    root = tmp_path / "trusted"
    root.mkdir()
    for relative in (
        "automation/local-execution-policy.json", "automation/local_review_evidence.js",
        "automation/schemas/local-execution-policy.schema.json",
        "automation/schemas/review-result.schema.json", ".github/prompts/implement.md",
        "automation/chatgpt-event-task-prompt.md",
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    (root / "src").mkdir()
    (root / "src/example.py").write_text("value = 1\n")
    (root / "docs/review").mkdir(parents=True)
    (root / "docs/review/phase-0a-invariant-audit.json").write_text('{"fixture":true}')
    (root / ".gitignore").write_text(".venv/\n")
    local.git(root, "init", "-q", "--initial-branch=main")
    local.git(root, "add", ".")
    local.git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
              "commit", "-qm", "base")
    local.git(root, "remote", "add", "origin", str(root))
    (root / ".venv").mkdir()
    sha = local.git(root, "rev-parse", "HEAD")
    gh = GitHubDouble(root, sha)
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = gh  # type: ignore[assignment]
    loop.repo_root = root
    loop.actor_login = loop.approver_login = "operator"
    loop.reviewer_login = "chatgpt-codex-connector[bot]"
    loop.default_branch = "main"
    loop.trusted_default_branch_sha = sha
    loop.pull_request_number = 3
    loop.deadline = time.monotonic() + 600
    loop.dry_run = False
    loop.log = lambda _message: None  # type: ignore[method-assign]
    loop.review_schema = json.loads(
        (root / "automation/schemas/review-result.schema.json").read_text()
    )
    monkeypatch.setattr(local, "utc_now", gh.tick)
    monkeypatch.setattr(local, "preflight_local_worker", lambda _config: None)
    real_mkdtemp = local.tempfile.mkdtemp
    monkeypatch.setattr(local.tempfile, "mkdtemp",
                        lambda **kwargs: real_mkdtemp(dir=tmp_path, **kwargs))
    return local.LocalExecution(root), loop, gh


def authority(loop: PhaseLoop, gh: GitHubDouble, kind: str) -> MarkerEvidence:
    payload: dict[str, Any] = {"schema_version": "1.0", "phase": "phase-0a", "head_sha": gh.head}
    if kind == "implementation":
        payload.update({"action": "IMPLEMENT_PHASE", "trigger": "PHASE_START",
                        "phase_prompt": "prompts/phases/phase-0a-security-fix.md"})
        name = "redteam-implementation-request"
    else:
        name = "redteam-ready-for-review"
    body = local.marker_body(name, payload)
    if kind == "review":
        body += "\n" + local.marker_body("redteam-invariant-audit", {
            "schema_version": "1.0", "phase": "phase-0a", "head_sha": gh.head,
            "audit_path": "docs/review/phase-0a-invariant-audit.json",
            "audit_digest": canonical_digest({"fixture": True}),
            "request_reference": "https://github.com/example/repo/pull/3#issuecomment-100",
        })
    item = gh.post_comment(3, body)
    gh.items[-1]["user"]["login"] = "github-actions[bot]"
    return MarkerEvidence(payload, item["html_url"], "github-actions[bot]", body)


def report(gh: GitHubDouble, count: int = 0) -> dict[str, Any]:
    return {"schema_version": "1.0", "phase": "phase-0a", "reviewed_sha": gh.head,
            "base_sha": gh.base, "verdict": "CHANGES_REQUESTED" if count else "PASS",
            "summary": "Complete independent fixture review",
            "findings": [{"id": f"FINDING-{index}", "severity": "HIGH",
                          "invariant_family": "authorization-lifecycle",
                          "requirement_id": "SAFE-001", "evidence": "src/example.py:1",
                          "required_fix": "Restore the invariant", "retest": ["fixture test"]}
                         for index in range(1, count + 1)],
            "required_checks": [{"name": name, "status": "PASS"} for name in REQUIRED_CHECK_ORDER]}


def reviewer_stub(gh: GitHubDouble, count: int = 0):  # type: ignore[no-untyped-def]
    def run(config: Any, prompt: str, schema: Any) -> LocalWorkerResult:
        assert config.role == "review"
        assert "/run/redteam-input/evidence.json" in prompt
        assert config.input_dir.is_dir()
        assert schema["type"] == "object"
        gh.tick()
        return LocalWorkerResult(SESSION, report(gh, count), "f" * 64)
    return run


@pytest.mark.parametrize("count", [0, 1, 3])
def test_complete_local_review_and_restart_reuses_all_verified_findings(
    harness: Any, monkeypatch: pytest.MonkeyPatch, count: int,
) -> None:
    backend, loop, gh = harness
    ready = authority(loop, gh, "review")
    state = loop.pr_state()
    calls = []
    run = reviewer_stub(gh, count)

    def worker(*args: Any) -> LocalWorkerResult:
        calls.append(args[0].workspace)
        return run(*args)

    monkeypatch.setattr(local, "run_local_worker", worker)
    backend.review(loop, state, ready, gh.base, loop.comments())
    evidence = local.LocalExecution(backend.root).find_review(
        loop, state, ready, gh.base, loop.comments())
    assert evidence is not None
    assert evidence.result == report(gh, count)
    assert evidence.author == "operator"
    assert len(gh.claims) == 1
    assert len(gh.items) == 3 + count
    backend.review(loop, state, ready, gh.base, loop.comments())
    assert len(calls) == 1
    assert len(gh.items) == 3 + count
    assert local.git(calls[0], "status", "--porcelain") == ""
    assert all("@codex" not in item["body"] for item in gh.items)


@pytest.mark.parametrize("mutation", ["none", "omit", "wrong_reference", "edited", "wrong_author"])
def test_fix_input_contains_every_bound_finding_body(
    harness: Any, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    backend, loop, gh = harness
    ready = authority(loop, gh, "review")
    state = loop.pr_state()
    monkeypatch.setattr(local, "run_local_worker", reviewer_stub(gh, 2))
    backend.review(loop, state, ready, gh.base, loop.comments())
    review = backend.find_review(loop, state, ready, gh.base, loop.comments())
    assert review is not None
    findings = [{"finding_key": f"FINDING-{index}",
                 "finding_reference": gh.items[index + 1]["html_url"],
                 "invariant_family": "authorization-lifecycle"} for index in (1, 2)]
    gate = {"phase": state.phase, "reviewed_sha": state.head_sha,
            "base_sha": gh.base, "verdict": "CHANGES_REQUESTED", "recorded_by": "operator",
            "evidence_format": "local-review-v1", "reviewer_login": "operator",
            "ready_reference": ready.url, "review_reference": review.url,
            "review_trigger_reference": review.trigger_url}
    gh.post_comment(3, local.marker_body("redteam-phase-gate", gate))
    gh.items[-1]["user"]["login"] = "github-actions[bot]"
    request = MarkerEvidence({"action": "FIX_REVIEW_FINDINGS", "review": {
        "reviewed_sha": state.head_sha, "review_reference": review.url,
        "finding_count": 2, "findings": findings,
    }}, "https://github.com/example/repo/pull/3#issuecomment-100", "github-actions[bot]", "")
    if mutation == "omit":
        request.payload["review"]["findings"] = findings[:1]
    elif mutation == "wrong_reference":
        findings[0]["finding_reference"] = ready.url
    elif mutation == "edited":
        gh.items[2]["updated_at"] = gh.tick()
    elif mutation == "wrong_author":
        gh.items[2]["user"]["login"] = "implementer"
    if mutation == "none":
        result = backend._fix_findings(loop, state, request, loop.comments())
        assert len(result) == 2
        assert [item["finding_key"] for item in result] == ["FINDING-1", "FINDING-2"]
        assert all(item["untrusted_finding"]["required_fix"] == "Restore the invariant"
                   for item in result)
    else:
        with pytest.raises(local.LocalExecutionBlocked):
            backend._fix_findings(loop, state, request, loop.comments())


def test_non_authorizing_projection_drift_does_not_block_current_request(harness: Any) -> None:
    backend, loop, gh = harness
    ready = authority(loop, gh, "review")
    state = loop.pr_state()
    gh.labels.remove("ai-needs-implementation")
    gh.labels.update({"ai-needs-review", "operator-note"})
    assert backend._current(loop, state, ready, "review")


def test_blocked_result_with_findings_records_no_retry_key(harness: Any) -> None:
    _backend, loop, gh = harness
    state = loop.pr_state()
    result = report(gh, 1)
    result["verdict"] = "BLOCKED"
    loop.dispatched_review_records = set()
    records = []
    gh.dispatch_workflow = lambda *args: records.append(args)
    loop.dispatch_review_record(state, local.ReviewEvidence(
        result, "https://github.com/example/repo/pull/3#issuecomment-3", "operator",
        state.head_sha, "https://github.com/example/repo/pull/3#issuecomment-1",
        "https://github.com/example/repo/pull/3#issuecomment-2",
    ))
    assert records[0][2]["finding_key"] == ""
    assert records[0][2]["verdict"] == "BLOCKED"


def test_complete_local_implementation_validates_then_pushes_one_child(
    harness: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, loop, gh = harness
    request = authority(loop, gh, "implementation")
    state = loop.pr_state()
    events = []
    real_git = local.git

    def worker(config: Any, prompt: str, _schema: Any) -> LocalWorkerResult:
        assert config.role == "implementation"
        assert request.url in prompt
        assert json.loads((config.input_dir / "request.json").read_text()) == request.payload
        (config.workspace / "src/example.py").write_text("value = 2\n")
        events.append("worker")
        return LocalWorkerResult(SESSION, {"status": "READY", "summary": "fixture"}, "f" * 64)

    def validation(config: Any, phase: str) -> LocalValidationResult:
        assert phase == state.phase
        assert "value = 2" in (config.workspace / "src/example.py").read_text()
        events.append("gate")
        return LocalValidationResult("PHASE_GATE=phase-0a PASS", "e" * 64)

    def git_double(workspace: Path, *arguments: str, **kwargs: Any) -> str:
        if "push" in arguments:
            assert events == ["worker", "gate"]
            assert "--force" not in arguments and "--force-with-lease" not in arguments
            gh.head = arguments[-1].split(":")[0]
            assert real_git(workspace, "rev-list", "--parents", "-n", "1", "HEAD") == (
                f"{gh.head} {state.head_sha}")
            events.append("push")
            return ""
        return real_git(workspace, *arguments, **kwargs)

    monkeypatch.setattr(local, "run_local_worker", worker)
    monkeypatch.setattr(local, "run_local_validation", validation)
    monkeypatch.setattr(local, "git", git_double)
    backend.implement(loop, state, request, loop.comments())
    assert events == ["worker", "gate", "push"]
    assert gh.head != state.head_sha
    assert len(gh.claims) == 1
    assert "redteam-local-implementation-result" in gh.items[-1]["body"]
    assert real_git(backend.root, "rev-parse", "HEAD") == state.head_sha


@pytest.mark.parametrize("kind", ["implementation", "review"])
@pytest.mark.parametrize("failure", ["claim", "start"])
def test_claim_or_start_acknowledgement_loss_never_restarts_worker(
    harness: Any, monkeypatch: pytest.MonkeyPatch, kind: str, failure: str,
) -> None:
    backend, loop, gh = harness
    source = authority(loop, gh, kind)
    state = loop.pr_state()
    gh.fail_claim = failure == "claim"
    gh.fail_post = failure == "start"
    calls = []
    monkeypatch.setattr(local, "run_local_worker", lambda *args: calls.append(args))

    def attempt() -> None:
        if kind == "review":
            backend.review(loop, state, source, gh.base, loop.comments())
        else:
            backend.implement(loop, state, source, loop.comments())

    with pytest.raises(local.LocalReconciliationRequired):
        attempt()
    gh.fail_claim = gh.fail_post = False
    with pytest.raises(local.LocalReconciliationRequired):
        attempt()
    assert calls == [] and len(gh.claims) == 1


@pytest.mark.parametrize("kind", ["implementation", "review"])
def test_legacy_inflight_cloud_input_requires_cutover_reconciliation(
    harness: Any, kind: str,
) -> None:
    backend, loop, gh = harness
    source = authority(loop, gh, kind)
    state = loop.pr_state()
    gh.post_comment(3, local.marker_body("redteam-local-codex-trigger", {
        "kind": kind, "head_sha": gh.head, "source_digest": "f" * 64,
    }))
    with pytest.raises(local.LocalReconciliationRequired, match="LEGACY_CLOUD"):
        if kind == "review":
            backend.review(loop, state, source, gh.base, loop.comments())
        else:
            backend.implement(loop, state, source, loop.comments())
    assert gh.claims == set()


@pytest.mark.parametrize("change", ["head", "main", "stop", "edit", "checks", "source"])
def test_live_authority_drift_prevents_review_start(harness: Any, change: str) -> None:
    backend, loop, gh = harness
    source = authority(loop, gh, "review")
    state = loop.pr_state()
    if change == "head":
        gh.head = "a" * 40
    elif change == "main":
        gh.base = "a" * 40
    elif change == "stop":
        gh.labels.add("ai-loop-blocked")
    elif change == "edit":
        gh.items[0]["updated_at"] = gh.tick()
    elif change == "source":
        gh.items[0]["body"] += "\nchanged"
    else:
        gh.check_status = "failure"
    with pytest.raises((local.LocalExecutionBlocked, PrerequisiteError)):
        backend.review(loop, state, source, state.base_sha, loop.comments())
    assert gh.claims == set()


@pytest.mark.parametrize("change", ["head", "main", "stop", "source", "checks", "timeline",
                                    "snapshot", "malformed", "wrong_binding", "duplicate_finding"])
def test_drift_or_bad_worker_result_cannot_publish_passing_review(
    harness: Any, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    backend, loop, gh = harness
    source = authority(loop, gh, "review")
    state = loop.pr_state()

    def worker(config: Any, _prompt: str, _schema: Any) -> LocalWorkerResult:
        result = report(gh)
        if change == "head":
            gh.head = "a" * 40
        elif change == "main":
            gh.base = "a" * 40
        elif change == "stop":
            gh.labels.add("ai-loop-blocked")
        elif change == "source":
            gh.items[0]["body"] += "\nchanged"
        elif change == "checks":
            gh.check_status = "failure"
        elif change == "timeline":
            gh.events.append({"event": "synchronize", "created_at": gh.tick()})
        elif change == "snapshot":
            (config.workspace / "src/example.py").write_text("tampered")
        elif change == "malformed":
            result["unknown"] = True
        elif change == "wrong_binding":
            result["reviewed_sha"] = "a" * 40
        elif change == "duplicate_finding":
            result = report(gh, 2)
            result["findings"][1] = result["findings"][0]
        gh.tick()
        return LocalWorkerResult(SESSION, result, "f" * 64)

    monkeypatch.setattr(local, "run_local_worker", worker)
    with pytest.raises((local.PhaseLoopError, PrerequisiteError)):
        backend.review(loop, state, source, state.base_sha, loop.comments())
    assert not any("redteam-local-review-result" in item["body"] for item in gh.items)


@pytest.mark.parametrize("mutation", ["protected", "symlink", "head", "empty", "gate_content",
                                       "missing_strict_audit"])
def test_implementation_changes_are_scoped_and_independently_checked(
    harness: Any, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    backend, loop, gh = harness
    source = authority(loop, gh, "implementation")
    if mutation == "missing_strict_audit":
        source.payload["invariant_audit"] = {"required": True}
        body = local.marker_body("redteam-implementation-request", source.payload)
        gh.items[0]["body"] = body
        source = MarkerEvidence(source.payload, source.url, source.author, body)
    state = loop.pr_state()

    def worker(config: Any, _prompt: str, _schema: Any) -> LocalWorkerResult:
        if mutation == "protected":
            (config.workspace / "automation/local-execution-policy.json").write_text("{}")
        elif mutation == "symlink":
            (config.workspace / "src/link.py").symlink_to("/etc/passwd")
        elif mutation == "head":
            local.git(config.workspace, "-c", "user.name=Fixture", "-c",
                      "user.email=fixture@example.invalid", "commit", "--allow-empty", "-m", "bad")
        elif mutation in {"gate_content", "missing_strict_audit"}:
            (config.workspace / "src/example.py").write_text("value = 2\n")
        return LocalWorkerResult(SESSION, {"status": "READY", "summary": "fixture"}, "f" * 64)

    def validation(config: Any, _phase: str) -> LocalValidationResult:
        if mutation == "gate_content":
            (config.workspace / "src/example.py").write_text("value = 3\n")
        return LocalValidationResult("PASS", "f" * 64)

    monkeypatch.setattr(local, "run_local_worker", worker)
    monkeypatch.setattr(local, "run_local_validation", validation)
    with pytest.raises(local.LocalExecutionBlocked):
        backend.implement(loop, state, source, loop.comments())
    assert gh.head == state.head_sha
    assert not any("implementation-result" in item["body"] for item in gh.items)


def test_partial_review_publication_loss_requires_reconciliation(
    harness: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, loop, gh = harness
    ready = authority(loop, gh, "review")
    state = loop.pr_state()
    calls = []

    def worker(config: Any, prompt: str, schema: Any) -> LocalWorkerResult:
        calls.append(config.workspace)
        gh.fail_post = True
        return reviewer_stub(gh, 2)(config, prompt, schema)

    monkeypatch.setattr(local, "run_local_worker", worker)
    with pytest.raises(local.LocalReconciliationRequired, match="PUBLICATION"):
        backend.review(loop, state, ready, gh.base, loop.comments())
    gh.fail_post = False
    assert len(gh.items) == 3  # ready, start, one finding with a lost acknowledgement
    with pytest.raises(local.LocalReconciliationRequired, match="ATTEMPT"):
        local.LocalExecution(backend.root).review(loop, state, ready, gh.base, loop.comments())
    assert len(calls) == 1


@pytest.mark.parametrize("kind", ["implementation", "review"])
def test_dry_run_does_not_create_claim_workspace_or_model(harness: Any, kind: str) -> None:
    backend, loop, gh = harness
    source = authority(loop, gh, kind)
    loop.dry_run = True
    state = loop.pr_state()
    if kind == "review":
        backend.review(loop, state, source, gh.base, loop.comments())
    else:
        backend.implement(loop, state, source, loop.comments())
    assert gh.claims == set()
    assert len(gh.items) == 1
    assert list(backend.root.parent.glob("redteam-local-*")) == []


@pytest.mark.parametrize("path", ["AGENTS.md", "automation/x.py", "scripts/ci/x.py", "../src/x",
                                  "src/../AGENTS.md", "src//x", "src/.git/x", "/src/x",
                                  "src\\x", "docs/requirements.md", "tests/.codex/x"])
def test_protected_and_ambiguous_paths_are_rejected(path: str) -> None:
    assert not local.allowed_product_path(path)


@given(st.text(alphabet="abc123_-", min_size=1, max_size=30))
def test_product_scope_does_not_allow_parent_traversal(name: str) -> None:
    assert local.allowed_product_path(f"src/{name}.py")
    assert not local.allowed_product_path(f"src/../{name}.py")


def test_policy_rejects_cloud_fallback_and_unknown_controls(harness: Any) -> None:
    backend, _loop, _gh = harness
    path = backend.root / "automation/local-execution-policy.json"
    policy = json.loads(path.read_text())
    policy["cloud_fallback"] = True
    path.write_text(json.dumps(policy))
    with pytest.raises(local.LocalExecutionBlocked, match="POLICY"):
        local.LocalExecution(backend.root)


def test_host_model_preferences_do_not_forward_tool_or_provider_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = (b'model="fixture-model"\nmodel_reasoning_effort="medium"\n'
           b'[mcp_servers.fixture]\ncommand="false"\n')
    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: io.BytesIO(raw))
    assert local.trusted_model_settings() == {
        "model": "fixture-model", "reasoning_effort": "medium",
    }


@pytest.mark.parametrize("raw", [b"model=123", b'model="unterminated'])
def test_malformed_host_model_preferences_fail_closed(
    monkeypatch: pytest.MonkeyPatch, raw: bytes,
) -> None:
    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: io.BytesIO(raw))
    with pytest.raises(local.LocalExecutionBlocked):
        local.trusted_model_settings()


@pytest.mark.parametrize("payload", [{"x": "a" * 60000}, {"x": "-->"}, {"x": "漢" * 20000}])
def test_unpublishable_markers_never_truncate(payload: dict[str, str]) -> None:
    with pytest.raises(local.LocalExecutionBlocked):
        local.marker_body("fixture", payload)


def test_journal_is_immutable_and_private(tmp_path: Path) -> None:
    local.LocalExecution._journal(tmp_path, "01-claim", {"state": "claimed"})
    path = tmp_path / "01-claim.json"
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        local.LocalExecution._journal(tmp_path, "01-claim", {"state": "replay"})


def test_documented_script_entry_point_can_load_package_from_other_directory(
    tmp_path: Path,
) -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(ROOT / "automation/run_phase_loop.py"), "--help"],
        cwd=tmp_path, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0
    assert "local independent review" in result.stdout


@settings(max_examples=20)
@given(st.lists(st.sampled_from(["launch", "restart", "ack_lost"]), min_size=1, max_size=20))
def test_permanent_claim_allows_at_most_one_launch(sequence: list[str]) -> None:
    # Same production claim method, a durable Git ref store, arbitrary restart/ack sequences.
    gh = GitHubDouble(ROOT, "a" * 40)
    loop = PhaseLoop.__new__(PhaseLoop)
    loop.github = gh  # type: ignore[assignment]
    loop.default_branch = "main"
    loop.pull_request_number = 3
    state = loop.pr_state()
    backend = local.LocalExecution(ROOT)
    launched = 0
    for action in sequence:
        if action == "restart":
            backend = local.LocalExecution(ROOT)
            continue
        gh.fail_claim = action == "ack_lost"
        try:
            backend._claim(loop, state, "review", canonical_digest({"source": "fixed"}))
            launched += 1
        except local.LocalReconciliationRequired:
            pass
    assert launched <= 1
