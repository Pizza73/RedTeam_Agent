from __future__ import annotations

import hashlib
import json
import os
import signal
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule
from jsonschema import Draft202012Validator

from automation import local_worker as worker

SESSION = "13b3a7c0-c9e7-4de8-9d82-07831d2a6f33"
SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict"],
    "properties": {"verdict": {"enum": ["PASS", "BLOCKED"]}},
}


def _events() -> list[dict[str, Any]]:
    return [
        {"type": "thread.started", "thread_id": SESSION},
        {"type": "turn.started"},
        {"type": "item.completed", "item": {"type": "agent_message", "text": '{"verdict":"PASS"}'}},
        {"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}},
    ]


def _encode(events: list[dict[str, Any]]) -> bytes:
    return ("\n".join(json.dumps(event) for event in events) + "\n").encode()


@pytest.fixture
def config(tmp_path: Path) -> worker.LocalWorkerConfig:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".git").mkdir()
    (workspace / ".venv").mkdir()
    (workspace / "AGENTS.md").write_text("Trusted instructions\n")
    return worker.LocalWorkerConfig(workspace, "review")


@pytest.fixture
def synthetic_account(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Command-construction tests must never inspect the invoking CLI account."""
    account = tmp_path / "synthetic-account"
    account.mkdir()
    environment = worker.sanitized_environment({"HOME": str(account)})
    monkeypatch.setattr(worker, "sanitized_environment", lambda _source: dict(environment))
    return account


def test_complete_fresh_session_has_exact_transcript_digest() -> None:
    output = _encode(_events())
    result = worker.parse_worker_output(output)
    assert result.session_id == SESSION
    assert result.final_json == {"verdict": "PASS"}
    assert result.transcript_sha256 == hashlib.sha256(output).hexdigest()


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_thread",
        "duplicate_turn",
        "missing_start",
        "missing_completion",
        "trailing",
        "error",
        "turn_failed",
        "unknown",
        "invalid_session",
        "non_object",
        "bad_message",
        "bad_item",
        "item_error",
        "premature_complete",
        "invalid_final",
        "duplicate_final_key",
        "nonfinite_final",
        "bad_unicode",
        "truncated",
        "blank_line",
    ],
)
def test_malformed_or_uncertain_result_fails_closed(mutation: str) -> None:
    events = _events()
    if mutation == "duplicate_thread":
        events.insert(1, events[0])
    elif mutation == "duplicate_turn":
        events.insert(2, events[1])
    elif mutation == "missing_start":
        del events[0]
    elif mutation == "missing_completion":
        events.pop()
    elif mutation == "trailing":
        events.append(events[-1])
    elif mutation in {"error", "turn_failed", "unknown"}:
        events[-1] = {"type": {"error": "error", "turn_failed": "turn.failed"}.get(mutation, "new")}
    elif mutation == "invalid_session":
        events[0]["thread_id"] = "fresh-session"
    elif mutation == "bad_message":
        events[2]["item"]["text"] = 1
    elif mutation == "bad_item":
        events[2]["item"] = "item"
    elif mutation == "item_error":
        events[2]["item"]["type"] = "error"
    elif mutation == "premature_complete":
        del events[2]
    elif mutation in {"invalid_final", "duplicate_final_key", "nonfinite_final"}:
        events[2]["item"]["text"] = {
            "invalid_final": "not json",
            "duplicate_final_key": '{"a":1,"a":2}',
            "nonfinite_final": '{"a":NaN}',
        }[mutation]
    output = _encode(events)
    if mutation == "non_object":
        output = b"[]\n"
    elif mutation == "bad_unicode":
        output = b"\xff\n"
    elif mutation == "truncated":
        output = output[:-1]
    elif mutation == "blank_line":
        output = b"\n" + output
    with pytest.raises(worker.LocalWorkerProtocolError):
        worker.parse_worker_output(output)


def test_duplicate_protocol_keys_are_rejected() -> None:
    with pytest.raises(worker.LocalWorkerProtocolError):
        worker.parse_worker_output(b'{"type":"error","type":"turn.completed"}\n')


def test_progress_message_is_not_the_structured_final() -> None:
    events = _events()
    events.insert(
        2, {"type": "item.completed", "item": {"type": "agent_message", "text": "Working"}}
    )
    assert worker.parse_worker_output(_encode(events)).final_json == {"verdict": "PASS"}


def test_native_startup_warning_is_advisory_but_never_an_answer() -> None:
    events = _events()
    warning = {
        "type": "item.completed",
        "item": {"id": "item_0", "type": "warning", "message": "Synthetic startup notice"},
    }
    events.insert(1, warning)
    assert worker.parse_worker_output(_encode(events)).final_json == {"verdict": "PASS"}
    events[1]["item"]["type"] = "error"
    with pytest.raises(worker.LocalWorkerProtocolError):
        worker.parse_worker_output(_encode(events))


def test_environment_allowlist_does_not_inherit_credentials_or_configuration() -> None:
    source = dict.fromkeys(
        [
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "SSH_AUTH_SOCK",
            "DBUS_SESSION_BUS_ADDRESS",
            "HTTP_PROXY",
            "PYTHONPATH",
            "BASH_ENV",
            "LD_PRELOAD",
            "GIT_CONFIG_COUNT",
            "CODEX_REMOTE",
            "CODEX_API_KEY",
            "CODEX_CI",
            "XDG_CONFIG_HOME",
        ],
        "untrusted-value",
    )
    source.update({"HOME": "/home/operator", "CODEX_HOME": "/home/operator/.codex"})
    environment = worker.sanitized_environment(source)
    assert environment["HOME"] == source["HOME"]
    assert environment["CODEX_HOME"] == source["CODEX_HOME"]
    assert set(environment).isdisjoint(set(source) - {"HOME", "CODEX_HOME"})
    assert "untrusted-value" not in environment.values()


@pytest.mark.parametrize(
    "source", [{}, {"HOME": "relative"}, {"HOME": "/home/u", "CODEX_HOME": "bad"}]
)
def test_invalid_account_location_rejected(source: dict[str, str]) -> None:
    with pytest.raises(worker.LocalWorkerPrerequisiteError):
        worker.sanitized_environment(source)


@pytest.mark.parametrize("role", ["review", "implementation"])
def test_namespace_mounts_only_runtime_workspace_and_readonly_native_auth(
    config: worker.LocalWorkerConfig,
    tmp_path: Path,
    role: str,
) -> None:
    config = replace(config, role=role)
    environment = worker.sanitized_environment({"HOME": str(tmp_path / "account")})
    schema = tmp_path / "schema.json"
    schema.write_text("{}")
    command = worker._outer_command(config, environment, schema, native_auth=False)
    assert command[0] == "/usr/bin/bwrap"
    assert "--unshare-all" in command and "--die-with-parent" in command
    assert "--clearenv" in command
    assert command[1:4] != ["--ro-bind", "/", "/"]
    assert str(tmp_path / "account" / ".config") not in command
    index = command.index(str(config.workspace))
    assert command[index - 1] == ("--ro-bind" if role == "review" else "--bind")
    if role == "implementation":
        git_index = command.index(str(config.workspace / ".git"))
        assert command[git_index - 1] == "--ro-bind"


def test_tool_profile_denies_auth_and_network_and_protects_git_and_governance(
    config: worker.LocalWorkerConfig,
) -> None:
    config = replace(config, role="implementation")
    account = Path("/home/operator/.codex")
    schema = config.workspace.parent / "schema.json"
    options = worker._codex_options(config, account, schema)
    values = dict(item.split("=", 1) for item in options[1::2])
    assert values["approval_policy"] == '"never"'
    assert values[f"permissions.{worker.PROFILE}.network.enabled"] == "false"
    filesystem = values[f"permissions.{worker.PROFILE}.filesystem"]
    assert f'{json.dumps(str(account))}="deny"' in filesystem
    assert f'{json.dumps(str(config.workspace))}="write"' in filesystem
    for path in worker.PROTECTED_PATHS:
        assert f'{json.dumps(str(config.workspace / path))}="read"' in filesystem
    assert values["shell_environment_policy.inherit"] == '"none"'
    assert values["features.plugins"] == "false"
    assert values["features.hooks"] == "false"
    assert values["features.apps"] == "false"
    assert values["features.code_mode_host"] == "{enabled=true,disable_in_process_fallback=true}"
    assert "model" not in values


def test_trusted_input_and_dependency_mounts_are_readonly(
    config: worker.LocalWorkerConfig, tmp_path: Path
) -> None:
    inputs, dependency = tmp_path / "input", tmp_path / "dependency"
    inputs.mkdir()
    dependency.mkdir()
    (inputs / "request.json").write_text("{}")
    config = replace(config, role="implementation", input_dir=inputs, dependency_env=dependency)
    command = worker._outer_command(
        config, {"HOME": "/home/operator"}, inputs / "request.json", native_auth=False
    )
    assert "/run/redteam-input" in command
    assert "/tmp/redteam-loop-request.json" in command  # noqa: S108 - namespace mount only.
    index = command.index(str(dependency))
    assert command[index - 1] == "--ro-bind"


def test_review_mounts_ready_evidence_without_fabricated_implementation_request(
    config: worker.LocalWorkerConfig,
    tmp_path: Path,
) -> None:
    inputs = tmp_path / "review-input"
    inputs.mkdir()
    (inputs / "evidence.json").write_text('{"kind":"review-ready"}')
    config = replace(config, input_dir=inputs)
    worker._validate_config(config)
    command = worker._outer_command(
        config,
        {"HOME": "/home/operator"},
        inputs / "evidence.json",
        native_auth=False,
    )
    assert "/run/redteam-input" in command
    assert not any(path.endswith("redteam-loop-request.json") for path in command)
    with pytest.raises(worker.LocalWorkerPrerequisiteError, match="INPUT_EVIDENCE"):
        worker._validate_config(replace(config, role="implementation"))


def test_dependency_mountpoint_is_required_before_review_freeze(
    config: worker.LocalWorkerConfig,
    tmp_path: Path,
) -> None:
    dependency = tmp_path / "dependencies"
    dependency.mkdir()
    (config.workspace / ".venv").rmdir()
    with pytest.raises(worker.LocalWorkerPrerequisiteError, match="DEPENDENCY_MOUNTPOINT"):
        worker._validate_config(replace(config, dependency_env=dependency))


@pytest.mark.parametrize(
    "changes",
    [
        {"role": "cloud"},
        {"timeout_seconds": True},
        {"timeout_seconds": 0},
        {"max_output_bytes": 100},
        {"codex_binary": Path("/untrusted/attacker-codex")},
        {"model": "--shell-command"},
        {"reasoning_effort": "infinite"},
    ],
)
def test_invalid_launch_configuration_is_rejected(
    config: worker.LocalWorkerConfig,
    changes: dict[str, Any],
) -> None:
    with pytest.raises(worker.LocalWorkerPrerequisiteError):
        worker._validate_config(replace(config, **changes))


def test_project_configuration_and_protected_symlink_rejected(
    config: worker.LocalWorkerConfig,
) -> None:
    (config.workspace / ".codex").mkdir()
    with pytest.raises(worker.LocalWorkerPrerequisiteError, match="PROJECT_CONFIG"):
        worker._validate_config(config)
    (config.workspace / ".codex").rmdir()
    (config.workspace / "automation").symlink_to(config.workspace.parent)
    with pytest.raises(worker.LocalWorkerPrerequisiteError, match="PROTECTED_PATH_ESCAPE"):
        worker._validate_config(config)


def test_bounded_process_handles_stdout_stderr_and_hides_failure_text() -> None:
    with pytest.raises(worker.LocalWorkerProtocolError) as caught:
        worker._run_bounded(
            [
                sys.executable,
                "-c",
                "import sys; print('PRIVATE_DIAGNOSTIC',file=sys.stderr); sys.exit(1)",
            ],
            {"PATH": "/usr/bin:/bin"},
            b"",
            5,
            4096,
        )
    assert "PRIVATE_DIAGNOSTIC" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_bounded_process_limits_both_output_streams() -> None:
    with pytest.raises(worker.LocalWorkerProtocolError, match="OUTPUT_LIMIT"):
        worker._run_bounded(
            [sys.executable, "-c", "import sys; sys.stderr.write('x'*8192)"],
            {"PATH": "/usr/bin:/bin"},
            b"",
            5,
            1024,
        )


def test_timeout_terminates_process_group(tmp_path: Path) -> None:
    pidfile = tmp_path / "child.pid"
    script = (
        "import os,sys,time\n"
        "pid=os.fork()\n"
        "if pid == 0:\n time.sleep(30)\n"
        "else:\n open(sys.argv[1],'w').write(str(pid))\n time.sleep(30)\n"
    )
    with pytest.raises(worker.LocalWorkerTimeoutError):
        worker._run_bounded(
            [sys.executable, "-c", script, str(pidfile)], {"PATH": "/usr/bin:/bin"}, b"", 1, 1024
        )
    child_pid = int(pidfile.read_text())
    # SIGKILL delivery and reaping are asynchronous. Bound the observation, not the assertion.
    for _ in range(100):
        try:
            state = Path(f"/proc/{child_pid}/stat").read_text().split()[2]
        except (FileNotFoundError, ProcessLookupError):
            return
        if state == "Z":
            return
        time.sleep(0.01)
    pytest.fail("worker descendant survived process-group cancellation")


def test_worker_launch_is_fresh_and_schema_validated(
    config: worker.LocalWorkerConfig,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_account: Path,
) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr(worker, "preflight_local_worker", lambda _config: None)

    def run(
        command: list[str], _env: dict[str, str], _prompt: bytes, _timeout: int, _limit: int
    ) -> bytes:
        captured.append(command)
        return _encode(_events())

    monkeypatch.setattr(worker, "_run_bounded", run)
    result = worker.run_local_worker(config, "Trusted task", SCHEMA)
    assert result.final_json == {"verdict": "PASS"}
    command = captured[0]
    assert str(synthetic_account) in command
    assert "exec" in command and "--ephemeral" in command and "--ignore-user-config" in command
    assert "--ignore-rules" in command and "--json" in command and "--strict-config" in command
    assert not {
        "cloud",
        "resume",
        "fork",
        "--remote",
        "--dangerously-bypass-approvals-and-sandbox",
    }.intersection(command)
    bad_schema = dict(SCHEMA, properties={"verdict": {"const": "BLOCKED"}})
    with pytest.raises(worker.LocalWorkerProtocolError, match="SCHEMA_REJECTED"):
        worker.run_local_worker(config, "Trusted task", bad_schema)


def test_transport_schema_never_replaces_conditional_review_validation(
    config: worker.LocalWorkerConfig,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_account: Path,
) -> None:
    schema_path = (
        Path(__file__).resolve().parents[2] / "automation/schemas/review-result.schema.json"
    )
    original = json.loads(schema_path.read_text())
    transport = worker._transport_schema(original)
    assert "allOf" not in transport and "allOf" in original
    assert transport["properties"]["schema_version"] == {"enum": ["1.0"], "type": "string"}
    assert transport["additionalProperties"] is False
    invalid = {
        "schema_version": "1.0",
        "phase": "phase-0c",
        "reviewed_sha": "1" * 40,
        "base_sha": "2" * 40,
        "verdict": "CHANGES_REQUESTED",
        "summary": "Synthetic",
        "findings": [],
        "required_checks": [],
    }
    assert Draft202012Validator(transport).is_valid(invalid)
    assert not Draft202012Validator(original).is_valid(invalid)
    events = _events()
    events[2]["item"]["text"] = json.dumps(invalid)
    monkeypatch.setattr(worker, "preflight_local_worker", lambda _config: None)
    monkeypatch.setattr(worker, "_run_bounded", lambda *_args: _encode(events))
    with pytest.raises(worker.LocalWorkerProtocolError, match="SCHEMA_REJECTED"):
        worker.run_local_worker(config, "Synthetic review", original)


def test_remote_transport_schema_references_fail_before_any_fetch() -> None:
    with pytest.raises(worker.LocalWorkerPrerequisiteError, match="UNSUPPORTED_TRANSPORT_SCHEMA"):
        worker._transport_schema({"$ref": "https://example.invalid/remote-schema"})


def test_validation_has_no_native_auth_or_network_and_requires_phase_gate_marker(
    config: worker.LocalWorkerConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_account: Path,
) -> None:
    dependencies = tmp_path / "dependency"
    dependencies.mkdir()
    config = replace(config, role="implementation", dependency_env=dependencies)
    monkeypatch.setattr(worker, "_verify_executables", lambda _config: None)
    captured: list[list[str]] = []

    def run(
        command: list[str], _env: dict[str, str], _prompt: bytes, _timeout: int, _limit: int
    ) -> bytes:
        captured.append(command)
        return b"checks passed\nPHASE_GATE=phase-0c PASS\n"

    monkeypatch.setattr(worker, "_run_bounded", run)
    result = worker.run_local_validation(config, "phase-0c")
    assert result.stdout.endswith("PHASE_GATE=phase-0c PASS\n")
    command = captured[0]
    assert str(synthetic_account) in command
    assert "--share-net" not in command
    assert not any(item.endswith("/auth.json") for item in command)
    assert command[-3:] == ["/bin/bash", "scripts/ci/run_phase_gate.sh", "phase-0c"]
    with pytest.raises(worker.LocalWorkerPrerequisiteError, match="INVALID_PHASE"):
        worker.run_local_validation(config, "phase-0c;echo unsafe")


def test_keyboard_interrupt_also_cancels_group(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[int] = []
    original = os.killpg

    def killpg(pid: int, sig: int) -> None:
        called.append(sig)
        original(pid, sig)

    monkeypatch.setattr(worker.os, "killpg", killpg)
    monkeypatch.setattr(
        worker.selectors.DefaultSelector,
        "select",
        lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        worker._run_bounded(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            {"PATH": "/usr/bin:/bin"},
            b"",
            5,
            1024,
        )
    assert signal.SIGKILL in called


class WorkerProtocolStateMachine(RuleBasedStateMachine):
    """An independent protocol oracle exercises restart/replay/error interleavings."""

    def __init__(self) -> None:
        super().__init__()
        self.events: list[dict[str, Any]] = []
        self.state = "new"
        self.final_answer = False

    @rule(
        kind=st.sampled_from(["thread", "turn", "warning", "progress", "answer", "done", "error"])
    )
    def append(self, kind: str) -> None:
        templates = {
            "thread": {"type": "thread.started", "thread_id": SESSION},
            "turn": {"type": "turn.started"},
            "warning": {
                "type": "item.completed",
                "item": {"id": "notice", "type": "warning", "message": "Synthetic notice"},
            },
            "progress": {
                "type": "item.completed",
                "item": {"id": "progress", "type": "agent_message", "text": "Working"},
            },
            "answer": {
                "type": "item.completed",
                "item": {"id": "answer", "type": "agent_message", "text": '{"verdict":"PASS"}'},
            },
            "done": {"type": "turn.completed", "usage": {}},
            "error": {"type": "error", "message": "Synthetic error"},
        }
        self.events.append(templates[kind])
        if self.state == "new" and kind == "thread":
            self.state = "ready"
        elif self.state == "ready" and kind == "warning":
            pass
        elif self.state == "ready" and kind == "turn":
            self.state = "running"
        elif self.state == "running" and kind in {"warning", "progress", "answer"}:
            if kind != "warning":
                self.final_answer = kind == "answer"
        elif self.state == "running" and kind == "done" and self.final_answer:
            self.state = "complete"
        else:
            self.state = "invalid"

    @invariant()
    def only_one_complete_fresh_turn_is_accepted(self) -> None:
        if self.state == "complete":
            assert worker.parse_worker_output(_encode(self.events)).final_json == {
                "verdict": "PASS"
            }
        else:
            with pytest.raises(worker.LocalWorkerProtocolError):
                worker.parse_worker_output(_encode(self.events))


TestWorkerProtocolStateMachine = WorkerProtocolStateMachine.TestCase
TestWorkerProtocolStateMachine.settings = settings(max_examples=80, stateful_step_count=25)
