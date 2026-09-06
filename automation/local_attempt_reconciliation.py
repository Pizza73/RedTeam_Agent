"""Close known BLOCKED attempts; never authorize replay or remove a claim.

Legacy journals have no launcher PID: explicit operator stopped attestation plus a
conservative process scan is required. This is host/operator evidence, not proof
against a compromised host. Future live publication follows the launcher's waited
worker return and requires no operator attestation.
"""
from __future__ import annotations

import argparse
import os
import re
import stat
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any
from uuid import UUID

from automation.local_execution import (
    LocalExecution,
    LocalReconciliationRequired,
    git,
    marker_body,
    utc_now,
)
from automation.run_phase_loop import (
    GitHubClient,
    PhaseLoop,
    canonical_digest,
    marker_payloads,
    strict_json_loads,
)

START = "redteam-local-implementation-start"
TERMINAL = "redteam-local-implementation-terminal"
RESULT = "redteam-local-implementation-result"
CONFIRMATION = "RECONCILE_STOPPED_BLOCKED_NO_OUTPUT"
LEGACY_LAUNCHER = "1befa35ece8b4f0875c002433d4effe9f01b1cd6"
START_KEYS = {"schema_version", "phase", "head_sha", "base_sha", "request_reference",
              "source_digest", "policy_digest", "run_id", "started_at"}
TERMINAL_KEYS = START_KEYS | {"start_reference", "claim_reference", "implementation_session_id",
    "transcript_sha256", "outcome", "completion_basis", "completed_at", "journal_digest"}


def _typed_boundary(function: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(function)
    def bounded(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            raise LocalReconciliationRequired("LOCAL_ATTEMPT_RECONCILIATION_REJECTED") from None
    return bounded


def _require(value: bool) -> None:
    if not value:
        raise LocalReconciliationRequired("LOCAL_ATTEMPT_RECONCILIATION_REJECTED")


def _closed(value: Any, keys: set[str]) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == keys)
    return value


def _read(directory: Path, name: str) -> dict[str, Any]:
    path = directory / name
    metadata = path.lstat()
    _require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
             and metadata.st_nlink == 1 and metadata.st_size <= 100_000
             and metadata.st_mode & 0o077 == 0)
    value = strict_json_loads(path.read_text())
    _require(isinstance(value, dict))
    return value


def _start(value: dict[str, Any]) -> None:
    _closed(value, START_KEYS)
    _require(value["schema_version"] == "1.0" and value["phase"] in
             {"phase-0a", "phase-0b", "phase-0c", "phase-1", "phase-2", "phase-3",
              "phase-4", "phase-5"})
    for name, length in (("head_sha", 40), ("base_sha", 40),
                         ("source_digest", 64), ("policy_digest", 64)):
        _require(isinstance(value[name], str) and
                 re.fullmatch(f"[0-9a-f]{{{length}}}", value[name]) is not None)
    _uuid(value["run_id"])
    _timestamp(value["started_at"])


def _uuid(value: Any) -> None:
    try:
        _require(isinstance(value, str) and str(UUID(value)) == value)
    except (ValueError, TypeError, AttributeError):
        raise LocalReconciliationRequired("LOCAL_ATTEMPT_INVALID_UUID") from None


def _timestamp(value: Any) -> datetime:
    try:
        _require(isinstance(value, str) and value.endswith("Z"))
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise LocalReconciliationRequired("LOCAL_ATTEMPT_INVALID_TIME") from None


def _digest(value: Any) -> None:
    _require(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None)


def _claim_reference(start: dict[str, Any], number: int) -> str:
    return (f"refs/redteam-local-attempts/pr-{number}/{start['phase']}/implementation/"
            f"{start['head_sha']}/{start['source_digest']}")


def _validate_terminal(value: dict[str, Any], start: dict[str, Any],
                       comment: dict[str, Any], number: int) -> None:
    _closed(value, TERMINAL_KEYS)
    _require(all(value.get(key) == start[key] for key in START_KEYS))
    _require(value["outcome"] == "BLOCKED_NO_OUTPUT" and
             value["completion_basis"] in {"waited-worker-return",
                                            "operator-stopped-legacy-attestation"})
    _require(value["claim_reference"] == _claim_reference(start, number))
    _uuid(value["implementation_session_id"])
    _digest(value["transcript_sha256"])
    _digest(value["journal_digest"])
    completed = _timestamp(value["completed_at"])
    _require(_timestamp(start["started_at"]) <= completed <=
             _timestamp(comment["created_at"]) + timedelta(seconds=60)
             and completed <= datetime.now(UTC) + timedelta(seconds=60))


def _verify_remote_claim(loop: Any, reference: str, head_sha: str) -> None:
    remote = loop.github.api_object(
        f"repos/{loop.github.repository}/git/ref/{reference.removeprefix('refs/')}")
    _require(remote.get("ref") == reference and remote.get("object", {}).get("sha")
             == head_sha and remote.get("object", {}).get("type") == "commit")


def _records(comments: list[dict[str, Any]], marker: str,
             actor: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    records = []
    for comment in comments:
        if comment.get("user", {}).get("login") != actor:
            continue
        values = marker_payloads(str(comment.get("body", "")), marker)
        if values:
            _require(len(values) == 1 and bool(comment.get("created_at")) and
                     comment["created_at"] == comment.get("updated_at"))
            records.append((comment, values[0]))
    return records


@_typed_boundary
def assert_attempts_resolved(loop: Any, state: Any, comments: list[dict[str, Any]],
                             *, include_current: bool = False) -> None:
    """Reject unresolved implementation starts before new input or base refresh.

Call with include_current=True immediately before a refresh write. Normal worker
selection retains its separate permanent same-HEAD cutover rejection.
"""
    if not any(START in str(item.get("body", "")) for item in comments):
        return
    terminals = _records(comments, TERMINAL, loop.actor_login)
    results = _records(comments, RESULT, loop.actor_login)
    starts = _records(comments, START, loop.actor_login)
    seen: set[str] = set()
    for comment, start in starts:
        _start(start)
        _require(start["run_id"] not in seen)
        seen.add(start["run_id"])
        if start["head_sha"] == state.head_sha and not include_current:
            continue
        _require(loop.github.is_ancestor(start["head_sha"], state.head_sha))
        candidates = [(item, value, kind) for kind, records in
                      ((TERMINAL, terminals), (RESULT, results)) for item, value in records
                      if value.get("run_id") == start["run_id"]]
        _require(len(candidates) == 1)
        item, value, kind = candidates[0]
        _require(all(value.get(key) == start[key] for key in START_KEYS)
                 and value.get("start_reference") == comment["html_url"]
                 and item["created_at"] >= comment["created_at"])
        if kind == TERMINAL:
            _validate_terminal(value, start, item, state.number)
            _verify_remote_claim(loop, value["claim_reference"], start["head_sha"])
        else:
            _closed(value, START_KEYS | {"start_reference", "implementation_session_id",
                                        "output_sha", "completed_at", "validation"})
            _require(value["validation"] == "PASS" and
                     re.fullmatch("[0-9a-f]{40}", value["output_sha"]) is not None)
            commit = loop.github.api_object(
                f"repos/{loop.github.repository}/git/commits/{value['output_sha']}")
            _require([p.get("sha") for p in commit.get("parents", [])] == [start["head_sha"]]
                     and loop.github.is_ancestor(value["output_sha"], state.head_sha))


def _no_active_launcher() -> None:
    # Never inspect environment/authentication data or print command lines.
    for path in Path("/proc").iterdir():
        if not path.name.isdigit() or int(path.name) == os.getpid():
            continue
        try:
            if path.stat().st_uid != os.getuid():
                continue
            args = (path / "cmdline").read_bytes().split(b"\0")
        except FileNotFoundError:
            continue
        except PermissionError:
            raise LocalReconciliationRequired("LOCAL_PROCESS_STATE_UNVERIFIABLE") from None
        _require(not any(argument.endswith((b"run_phase_loop.py", b"local_worker.py"))
                         or argument == b"automation.run_phase_loop" for argument in args))


@_typed_boundary
def publish_blocked_terminal(loop: Any, state: Any, directory: Path,
                             *, legacy: bool = False) -> str:
    """Caller must be the live launcher after waited BLOCKED return, or reconciler."""
    _require(loop.actor_login == loop.approver_login)
    _require(directory.is_absolute() and directory.resolve() == directory)
    metadata = directory.stat()
    _require(metadata.st_uid == os.getuid() and metadata.st_mode & 0o077 == 0)
    claimed = _closed(_read(directory, "01-claimed.json"), START_KEYS | {"claim_reference"})
    started = _closed(_read(directory, "02-started.json"), {"reference"})
    worker = _closed(_read(directory, "03-worker.json"),
                     {"session_id", "transcript_sha256", "result"})
    result = _closed(worker["result"], {"status", "summary"})
    _require(result["status"] == "BLOCKED" and isinstance(result["summary"], str))
    _uuid(worker["session_id"])
    _digest(worker["transcript_sha256"])
    start = {key: claimed[key] for key in START_KEYS}
    _start(start)
    _require(start["head_sha"] == state.head_sha and start["phase"] == state.phase)
    _require(not any((directory / name).exists() for name in
                     ("04-validated.json", "05-push-attempt.json", "06-published.json")))
    _require(git(directory / "workspace", "rev-parse", "HEAD") == state.head_sha)
    expected_claim = _claim_reference(start, state.number)
    _require(claimed["claim_reference"] == expected_claim)
    _verify_remote_claim(loop, expected_claim, state.head_sha)
    comments = loop.comments()
    matches = [(c, s) for c, s in _records(comments, START, loop.actor_login)
               if s.get("run_id") == start["run_id"]]
    _require(len(matches) == 1 and matches[0][1] == start and
             matches[0][0].get("html_url") == started["reference"])
    _require(not any(p.get("run_id") == start["run_id"] for _, p in
                     _records(comments, RESULT, loop.actor_login)))
    requests = [(c, p) for c, p in _records(comments, "redteam-implementation-request",
                                          "github-actions[bot]")
                if c.get("html_url") == start["request_reference"]]
    _require(len(requests) == 1 and canonical_digest({"request_url": start["request_reference"],
              "request": requests[0][1]}) == start["source_digest"])
    payload = {**start, "start_reference": started["reference"],
               "claim_reference": expected_claim, "implementation_session_id": worker["session_id"],
               "transcript_sha256": worker["transcript_sha256"], "outcome": "BLOCKED_NO_OUTPUT",
               "completion_basis": ("operator-stopped-legacy-attestation" if legacy
                                    else "waited-worker-return"),
               "journal_digest": canonical_digest([claimed, started, worker])}
    intent = directory / "07-terminal-intent.json"
    if intent.exists():
        saved = _closed(_read(directory, intent.name), TERMINAL_KEYS)
        _require(all(saved.get(key) == value for key, value in payload.items()))
        payload = saved
    else:
        payload["completed_at"] = utc_now()
    existing = [(c, p) for c, p in _records(comments, TERMINAL, loop.actor_login)
                if p.get("run_id") == start["run_id"]]
    if existing:
        _require(len(existing) == 1 and existing[0][1] == payload and intent.exists())
        _validate_terminal(payload, start, existing[0][0], state.number)
        return str(existing[0][0]["html_url"])
    _require(not intent.exists())  # Unknown publication: never resend.
    fresh = loop.github.pull_request(state.number)
    _require(fresh.get("state") == "open" and fresh.get("head", {}).get("sha") == state.head_sha)
    LocalExecution._journal(directory, "07-terminal-intent", payload)
    try:
        published = loop.github.post_comment(state.number, marker_body(TERMINAL, payload))
        verified = [(c, p) for c, p in _records(loop.comments(), TERMINAL, loop.actor_login)
                    if p.get("run_id") == start["run_id"]]
        _require(len(verified) == 1 and verified[0][1] == payload and
                 verified[0][0].get("html_url") == published.get("html_url"))
    except Exception:
        raise LocalReconciliationRequired("LOCAL_TERMINAL_PUBLICATION_UNCONFIRMED") from None
    return str(published["html_url"])


@_typed_boundary
def reconcile_blocked_attempt(loop: Any, attempt_directory: Path, *, confirmation: str) -> str:
    """Explicit operator-only close, not Resume and not a worker launch."""
    _require(confirmation == CONFIRMATION)
    loop.validate_local_checkout()
    _require(loop.github.current_login() == loop.actor_login == loop.approver_login)
    _no_active_launcher()
    state = loop.pr_state()
    workspace = attempt_directory / "workspace"
    for relative in ("automation/local_execution.py", "automation/local_worker.py"):
        _require(git(workspace, "show", f"{state.head_sha}:{relative}") ==
                 git(loop.repo_root, "show", f"{LEGACY_LAUNCHER}:{relative}"))
    return publish_blocked_terminal(loop, state, attempt_directory, legacy=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reconcile a stopped BLOCKED local attempt only")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--attempt-directory", type=Path, required=True)
    parser.add_argument("--confirmation", required=True, choices=[CONFIRMATION])
    args = parser.parse_args(argv)
    _require(args.pr > 0)
    try:
        loop = PhaseLoop(github=GitHubClient(args.repo),
                         repo_root=Path(__file__).resolve().parents[1],
                         pull_request_number=args.pr, poll_seconds=30,
                         deadline=time.monotonic() + 300, dry_run=False)
        reference = reconcile_blocked_attempt(loop, args.attempt_directory,
                                              confirmation=args.confirmation)
    except Exception:
        print("AI_LOOP=BLOCKED: LOCAL_ATTEMPT_RECONCILIATION_REJECTED", file=sys.stderr)
        return 2
    print(reference)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
