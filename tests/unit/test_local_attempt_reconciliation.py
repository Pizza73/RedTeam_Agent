from __future__ import annotations

import copy
import json
import re
import tempfile
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from automation import local_attempt_reconciliation as recovery
from automation.local_execution import LocalExecution, LocalReconciliationRequired, marker_body
from automation.run_phase_loop import canonical_digest


def _attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Any, Path]:
    directory = tmp_path / "attempt"
    directory.mkdir(mode=0o700)
    state = SimpleNamespace(number=3, phase="phase-0c", head_sha="a" * 40)
    request = {"phase": state.phase, "head_sha": state.head_sha}
    request_url = "https://github.com/example/repo/pull/3#issuecomment-1"
    start = {"schema_version": "1.0", "phase": state.phase, "head_sha": state.head_sha,
             "base_sha": "b" * 40, "request_reference": request_url,
             "source_digest": canonical_digest({"request_url": request_url, "request": request}),
             "policy_digest": "c" * 64, "run_id": "00000000-0000-4000-8000-000000000001",
             "started_at": "2026-09-06T10:00:00Z"}
    claim = (f"refs/redteam-local-attempts/pr-3/phase-0c/implementation/{state.head_sha}/"
             f"{start['source_digest']}")
    items: list[dict[str, Any]] = []

    def post(number: int, body: str, author: str = "operator") -> dict[str, Any]:
        assert number == 3
        item = {"html_url": f"https://github.com/example/repo/pull/3#issuecomment-{len(items)+1}",
                "user": {"login": author}, "body": body,
                "created_at": "2026-09-06T10:00:01Z", "updated_at": "2026-09-06T10:00:01Z"}
        items.append(item)
        return item

    post(3, marker_body("redteam-implementation-request", request), "github-actions[bot]")
    posted = post(3, marker_body(recovery.START, start))
    LocalExecution._journal(directory, "01-claimed", {**start, "claim_reference": claim})
    LocalExecution._journal(directory, "02-started", {"reference": posted["html_url"]})
    LocalExecution._journal(directory, "03-worker", {
        "session_id": "00000000-0000-4000-8000-000000000002", "transcript_sha256": "d" * 64,
        "result": {"status": "BLOCKED", "summary": "bounded synthetic failure"}})
    github = SimpleNamespace(repository="example/repo", post_comment=post,
        current_login=lambda: "operator", is_ancestor=lambda a, b: True,
        api_object=lambda endpoint: {"ref": claim, "object": {"sha": state.head_sha,
                                                              "type": "commit"}},
        pull_request=lambda number: {"state": "open", "head": {"sha": state.head_sha}})
    loop = SimpleNamespace(github=github, actor_login="operator", approver_login="operator",
        comments=lambda: copy.deepcopy(items), pr_state=lambda: state, repo_root=tmp_path,
        validate_local_checkout=lambda: None, items=items)
    monkeypatch.setattr(recovery, "git", lambda *args: state.head_sha)
    monkeypatch.setattr(recovery, "utc_now", lambda: "2026-09-06T10:00:02Z")
    return loop, state, directory


@pytest.fixture
def attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Any, Path]:
    return _attempt(tmp_path, monkeypatch)


def rewrite(directory: Path, name: str, mutate: Any) -> None:
    path = directory / name
    value = json.loads(path.read_text())
    mutate(value)
    path.write_text(json.dumps(value))


def test_known_blocked_publishes_once_and_preserves_claim(attempt: Any) -> None:
    loop, state, directory = attempt
    reference = recovery.publish_blocked_terminal(loop, state, directory)
    assert recovery.publish_blocked_terminal(loop, state, directory) == reference
    assert len(loop.items) == 3
    assert (directory / "01-claimed.json").exists()
    recovery.assert_attempts_resolved(loop, state, loop.comments(), include_current=True)


@pytest.mark.parametrize("name", ["04-validated.json", "05-push-attempt.json", "06-published.json"])
def test_later_stage_never_closed_as_no_output(attempt: Any, name: str) -> None:
    loop, state, directory = attempt
    (directory / name).touch()
    with pytest.raises(LocalReconciliationRequired):
        recovery.publish_blocked_terminal(loop, state, directory)
    assert len(loop.items) == 2


@pytest.mark.parametrize("filename,key,value", [
    ("01-claimed.json", "head_sha", "e" * 40),
    ("01-claimed.json", "source_digest", "e" * 64),
    ("01-claimed.json", "claim_reference", "refs/other"),
    ("02-started.json", "reference", "https://github.com/example/repo/pull/3#issuecomment-9"),
    ("03-worker.json", "session_id", "not-a-uuid"),
    ("03-worker.json", "transcript_sha256", "bad"),
    ("03-worker.json", "result", {"status": "READY", "summary": "ok"}),
    ("03-worker.json", "extra", True),
])
def test_journal_mismatch_rejected(attempt: Any, filename: str, key: str, value: Any) -> None:
    loop, state, directory = attempt
    rewrite(directory, filename, lambda record: record.update({key: value}))
    with pytest.raises((LocalReconciliationRequired, ValueError)):
        recovery.publish_blocked_terminal(loop, state, directory)
    assert len(loop.items) == 2


def test_remote_drift_rejected_before_intent(attempt: Any) -> None:
    loop, state, directory = attempt
    loop.github.pull_request = lambda number: {"state": "open", "head": {"sha": "f" * 40}}
    with pytest.raises(LocalReconciliationRequired):
        recovery.publish_blocked_terminal(loop, state, directory)
    assert not (directory / "07-terminal-intent.json").exists()


def test_unknown_publication_does_not_resend(attempt: Any) -> None:
    loop, state, directory = attempt
    def failed(*args: Any) -> None:
        raise RuntimeError("synthetic transport failure")
    loop.github.post_comment = failed
    with pytest.raises(LocalReconciliationRequired):
        recovery.publish_blocked_terminal(loop, state, directory)
    assert (directory / "07-terminal-intent.json").exists()
    loop.github.post_comment = lambda *args: pytest.fail("must not replay")
    with pytest.raises(LocalReconciliationRequired):
        recovery.publish_blocked_terminal(loop, state, directory)


def test_lost_ack_readback_is_idempotent(attempt: Any) -> None:
    loop, state, directory = attempt
    original = loop.github.post_comment
    def lost_ack(*args: Any) -> None:
        original(*args)
        raise RuntimeError("lost acknowledgment")
    loop.github.post_comment = lost_ack
    with pytest.raises(LocalReconciliationRequired):
        recovery.publish_blocked_terminal(loop, state, directory)
    loop.github.post_comment = lambda *args: pytest.fail("must not replay")
    assert recovery.publish_blocked_terminal(loop, state, directory).endswith("-3")


def test_unresolved_old_head_cannot_be_bypassed(attempt: Any) -> None:
    loop, state, directory = attempt
    later = SimpleNamespace(head_sha="e" * 40, number=3)
    with pytest.raises(LocalReconciliationRequired):
        recovery.assert_attempts_resolved(loop, later, loop.comments())
    recovery.publish_blocked_terminal(loop, state, directory)
    recovery.assert_attempts_resolved(loop, later, loop.comments())


def test_refresh_rejects_current_unresolved_attempt(attempt: Any) -> None:
    loop, state, _ = attempt
    recovery.assert_attempts_resolved(loop, state, loop.comments())
    with pytest.raises(LocalReconciliationRequired):
        recovery.assert_attempts_resolved(loop, state, loop.comments(), include_current=True)


def test_edited_terminal_and_ambiguous_terminal_rejected(attempt: Any) -> None:
    loop, state, directory = attempt
    recovery.publish_blocked_terminal(loop, state, directory)
    loop.items.append(copy.deepcopy(loop.items[-1]))
    with pytest.raises(LocalReconciliationRequired):
        recovery.assert_attempts_resolved(loop, state, loop.comments(), include_current=True)
    loop.items.pop()
    loop.items[-1]["updated_at"] = "2026-09-06T11:00:00Z"
    with pytest.raises(LocalReconciliationRequired):
        recovery.assert_attempts_resolved(loop, state, loop.comments(), include_current=True)


def test_operator_confirmation_and_process_check_required(attempt: Any,
                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    loop, _, directory = attempt
    with pytest.raises(LocalReconciliationRequired):
        recovery.reconcile_blocked_attempt(loop, directory, confirmation="yes")
    def active() -> None:
        raise LocalReconciliationRequired("still active")
    monkeypatch.setattr(recovery, "_no_active_launcher", active)
    with pytest.raises(LocalReconciliationRequired):
        recovery.reconcile_blocked_attempt(loop, directory, confirmation=recovery.CONFIRMATION)
    monkeypatch.setattr(recovery, "_no_active_launcher", lambda: None)
    assert recovery.reconcile_blocked_attempt(
        loop, directory, confirmation=recovery.CONFIRMATION).endswith("-3")


@given(st.text().filter(lambda value: re.fullmatch("[0-9a-f]{64}", value) is None))
def test_arbitrary_invalid_terminal_digest_rejected(value: str) -> None:
    with pytest.raises(LocalReconciliationRequired):
        recovery._digest(value)


@pytest.mark.parametrize("field,value", [
    ("claim_reference", "refs/other"), ("implementation_session_id", "bad"),
    ("journal_digest", "bad"), ("transcript_sha256", "bad"),
    ("completed_at", "2026-09-06T09:00:00Z"),
    ("completed_at", "2099-09-06T10:00:00Z"), ("outcome", "READY"),
])
def test_malformed_terminal_cannot_resolve_attempt(attempt: Any, field: str, value: Any) -> None:
    loop, state, directory = attempt
    recovery.publish_blocked_terminal(loop, state, directory)
    payload = recovery.marker_payloads(loop.items[-1]["body"], recovery.TERMINAL)[0]
    payload[field] = value
    loop.items[-1]["body"] = marker_body(recovery.TERMINAL, payload)
    with pytest.raises(LocalReconciliationRequired):
        recovery.assert_attempts_resolved(loop, state, loop.comments(), include_current=True)


def test_wrong_remote_claim_rejected(attempt: Any) -> None:
    loop, state, directory = attempt
    loop.github.api_object = lambda endpoint: {"ref": "wrong"}
    with pytest.raises(LocalReconciliationRequired):
        recovery.publish_blocked_terminal(loop, state, directory)


def test_duplicate_start_rejected(attempt: Any) -> None:
    loop, state, directory = attempt
    loop.items.append(copy.deepcopy(loop.items[-1]))
    with pytest.raises(LocalReconciliationRequired):
        recovery.publish_blocked_terminal(loop, state, directory)


def test_missing_journal_is_typed_reconciliation_stop(attempt: Any) -> None:
    loop, state, directory = attempt
    (directory / "03-worker.json").rename(directory / "saved-worker.json")
    with pytest.raises(LocalReconciliationRequired):
        recovery.publish_blocked_terminal(loop, state, directory)


def test_cli_sanitizes_unexpected_failure(monkeypatch: pytest.MonkeyPatch,
                                        capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    def failed(*args: Any) -> None:
        raise RuntimeError("synthetic-private-detail-do-not-publish")
    monkeypatch.setattr(recovery, "GitHubClient", failed)
    assert recovery.main(["--repo", "example/repo", "--pr", "3", "--attempt-directory",
                          str(tmp_path), "--confirmation", recovery.CONFIRMATION]) == 2
    captured = capsys.readouterr()
    assert "synthetic-private-detail" not in captured.err + captured.out
    assert captured.err.strip() == "AI_LOOP=BLOCKED: LOCAL_ATTEMPT_RECONCILIATION_REJECTED"


class AttemptClosureMachine(RuleBasedStateMachine):
    """Publication uncertainty cannot cause a second write or bypass refresh latch."""

    def __init__(self) -> None:
        super().__init__()
        self.temporary = tempfile.TemporaryDirectory()
        self.patch = pytest.MonkeyPatch()
        self.loop, self.state, self.directory = _attempt(Path(self.temporary.name), self.patch)
        self.original_post = self.loop.github.post_comment
        self.writes = 0
        self.has_intent = False

    @rule(ack=st.sampled_from(["success", "lost-before", "lost-after"]))
    def reconcile(self, ack: str) -> None:
        def post(*args: Any) -> dict[str, Any]:
            self.writes += 1
            if ack == "lost-before":
                raise RuntimeError("synthetic transport failure")
            value = self.original_post(*args)
            if ack == "lost-after":
                raise RuntimeError("synthetic lost ACK")
            return value
        self.loop.github.post_comment = post
        with suppress(LocalReconciliationRequired):
            recovery.publish_blocked_terminal(self.loop, self.state, self.directory)
        self.has_intent = (self.directory / "07-terminal-intent.json").exists()

    @invariant()
    def never_replay_or_refresh_unknown(self) -> None:
        assert self.writes <= 1
        assert (self.directory / "01-claimed.json").exists()
        if len(self.loop.items) == 2:
            with pytest.raises(LocalReconciliationRequired):
                recovery.assert_attempts_resolved(self.loop, self.state, self.loop.comments(),
                                                  include_current=True)
        else:
            recovery.assert_attempts_resolved(self.loop, self.state, self.loop.comments(),
                                              include_current=True)

    def teardown(self) -> None:
        self.patch.undo()
        self.temporary.cleanup()


TestAttemptClosureMachine = AttemptClosureMachine.TestCase
