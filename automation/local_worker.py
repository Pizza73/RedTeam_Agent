"""Fresh, isolated local Codex workers; never a Cloud or GitHub execution client.

The trusted caller owns the snapshot, authorization, schema, commit and publication.
Model output is untrusted data, not an attestation.  Linux bubblewrap separates the
worker from the host; Codex's nested permissions separate tools from native login.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import UUID, uuid4

from jsonschema import Draft202012Validator

CODEX_BINARY = Path("/usr/lib/chatgpt/resources/codex")
CODE_MODE_HOST_BINARY = Path("/usr/lib/chatgpt/resources/codex-code-mode-host")
BWRAP_BINARY = Path("/usr/bin/bwrap")
NODE_DIRECTORY = Path("/usr/lib/chatgpt/resources/cua_node/bin")
TOOL_TEMP_DIRECTORY = "/tmp/redteam-worker-tools"  # noqa: S108 - private namespace tmpfs.
PROFILE = "redteam-local-worker"
PROTECTED_PATHS = (
    ".git",
    ".github",
    ".codex",
    ".agents",
    ".venv",
    "AGENTS.md",
    "SystemDesign.md",
    "SystemDesign_AI_Control.md",
    "automation",
    "docs/requirements.md",
    "docs/acceptance-criteria.md",
    "docs/ai-development-loop.md",
    "docs/ai-loop-runbook.md",
    "docs/implementation-status.md",
    "docs/safety-invariants.md",
    "docs/threat-model.md",
    "prompts/phases",
    "scripts/ci",
    "pyproject.toml",
    "requirements.lock",
)
DISABLED_FEATURES = (
    "apps",
    "plugins",
    "remote_plugin",
    "recommended_plugins",
    "plugin_hooks",
    "hooks",
    "browser_use",
    "browser_use_external",
    "computer_use",
    "in_app_browser",
    "in_app_chat",
    "in_app_local_automation",
    "remote_control",
    "multi_agent",
    "multi_agent_mode",
    "multi_agent_v2",
    "enable_fanout",
    "memories",
    "external_agent_memory_import",
    "skill_search",
    "skill_mcp_dependency_install",
    "skill_env_var_dependency_prompt",
    "standalone_web_search",
    "search_tool",
    "shell_snapshot",
    "shell_snapshot_v2",
    "js_repl",
    "code_mode",
    "code_mode_only",
    "code_mode_prewarm",
    "image_generation",
    "workspace_dependencies",
    "codex_git_commit",
    "exec_permission_approvals",
    "request_permissions_tool",
    "request_rule",
    "tool_suggest",
)
RUNTIME_ROOTS = ("/usr", "/bin", "/lib", "/lib64")
SYSTEM_FILES = (
    "/etc/ssl",
    "/etc/ld.so.cache",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/localtime",
)


class LocalWorkerError(RuntimeError):
    """A static diagnostic safe to publish without subprocess output."""


class LocalWorkerPrerequisiteError(LocalWorkerError):
    """The local isolation contract could not be established."""


class LocalWorkerProtocolError(LocalWorkerError):
    """The fresh session did not produce one valid, complete result."""


class LocalWorkerTimeoutError(LocalWorkerError):
    """All worker processes were cancelled at the runtime bound."""


@dataclass(frozen=True)
class LocalWorkerConfig:
    workspace: Path
    role: Literal["implementation", "review"]
    codex_binary: Path = CODEX_BINARY
    bubblewrap_binary: Path = BWRAP_BINARY
    timeout_seconds: int = 1800
    max_output_bytes: int = 8 * 1024 * 1024
    # Only the trusted operator's configured selection, never inferred from PR content.
    model: str | None = None
    reasoning_effort: str | None = None
    input_dir: Path | None = None
    dependency_env: Path | None = None


@dataclass(frozen=True)
class LocalWorkerResult:
    session_id: str
    final_json: dict[str, Any]
    transcript_sha256: str


@dataclass(frozen=True)
class LocalValidationResult:
    stdout: str
    transcript_sha256: str


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LocalWorkerProtocolError("LOCAL_WORKER_DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise LocalWorkerProtocolError("LOCAL_WORKER_NONFINITE_JSON")


def _json_object(raw: str | bytes) -> dict[str, Any]:
    try:
        result = json.loads(raw, object_pairs_hook=_strict_object, parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise LocalWorkerProtocolError("LOCAL_WORKER_INVALID_JSON") from None
    if not isinstance(result, dict):
        raise LocalWorkerProtocolError("LOCAL_WORKER_EXPECTED_JSON_OBJECT")
    return result


def _transport_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Project generation syntax, not review authority, onto the CLI's supported subset.

    The original closed schema is always applied after generation, including its
    conditional verdict/finding constraints. This projection never validates results.
    """
    result: dict[str, Any] = {}
    for key, value in schema.items():
        if key in {"$schema", "$id", "allOf", "if", "then", "else"}:
            continue
        if key in {"$ref", "$dynamicRef", "$defs", "definitions"}:
            raise LocalWorkerPrerequisiteError("LOCAL_WORKER_UNSUPPORTED_TRANSPORT_SCHEMA")
        if key == "properties":
            result[key] = {name: _transport_schema(child) for name, child in value.items()}
        elif key == "items":
            result[key] = _transport_schema(value)
        elif key == "anyOf":
            result[key] = [_transport_schema(child) for child in value]
        elif key == "const":
            result["enum"] = [value]
        else:
            result[key] = value
    if "type" not in result and "enum" in result:
        value_types = {
            type(None): "null",
            str: "string",
            bool: "boolean",
            int: "integer",
            float: "number",
        }
        try:
            types = sorted({value_types[type(value)] for value in result["enum"]})
        except KeyError:
            raise LocalWorkerPrerequisiteError("LOCAL_WORKER_UNSUPPORTED_ENUM_SCHEMA") from None
        result["type"] = types[0] if len(types) == 1 else types
    return result


def parse_worker_output(output: bytes) -> LocalWorkerResult:
    """Validate framing; the caller still validates policy and exact-SHA bindings."""
    session_id: str | None = None
    started = completed = False
    final_text: str | None = None
    if not output or not output.endswith(b"\n"):
        raise LocalWorkerProtocolError("LOCAL_WORKER_TRUNCATED_OUTPUT")
    for line in output.splitlines():
        event = _json_object(line)
        kind = event.get("type")
        if completed:
            raise LocalWorkerProtocolError("LOCAL_WORKER_TRAILING_EVENT")
        if kind == "thread.started":
            value = event.get("thread_id")
            if session_id is not None or started or not isinstance(value, str):
                raise LocalWorkerProtocolError("LOCAL_WORKER_AMBIGUOUS_SESSION")
            try:
                if str(UUID(value)) != value:
                    raise ValueError
            except ValueError:
                raise LocalWorkerProtocolError("LOCAL_WORKER_INVALID_SESSION") from None
            session_id = value
        elif kind == "turn.started":
            if session_id is None or started:
                raise LocalWorkerProtocolError("LOCAL_WORKER_AMBIGUOUS_TURN")
            started = True
        elif kind in {"item.started", "item.updated", "item.completed"}:
            if not isinstance(event.get("item"), dict):
                raise LocalWorkerProtocolError("LOCAL_WORKER_INVALID_ITEM")
            item = event["item"]
            # CLI startup notices can occur after thread.started but before turn.started.
            # They are advisory only; neither an error nor a model answer is tolerated here.
            if not started:
                if (
                    session_id is None
                    or kind != "item.completed"
                    or set(item) != {"id", "type", "message"}
                    or item.get("type") != "warning"
                    or not isinstance(item.get("id"), str)
                    or not isinstance(item.get("message"), str)
                ):
                    raise LocalWorkerProtocolError("LOCAL_WORKER_INVALID_ITEM")
                continue
            if item.get("type") == "error":
                raise LocalWorkerProtocolError("LOCAL_WORKER_ERROR_EVENT")
            if kind == "item.completed" and item.get("type") == "agent_message":
                if not isinstance(item.get("text"), str):
                    raise LocalWorkerProtocolError("LOCAL_WORKER_INVALID_MESSAGE")
                final_text = item["text"]
        elif kind == "turn.completed":
            if not started or final_text is None:
                raise LocalWorkerProtocolError("LOCAL_WORKER_INCOMPLETE_TURN")
            completed = True
        else:
            # Includes error, turn.failed and protocol evolution; no success fallback.
            raise LocalWorkerProtocolError("LOCAL_WORKER_UNEXPECTED_EVENT")
    if not completed or session_id is None or final_text is None:
        raise LocalWorkerProtocolError("LOCAL_WORKER_INCOMPLETE_OUTPUT")
    return LocalWorkerResult(
        session_id, _json_object(final_text), hashlib.sha256(output).hexdigest()
    )


def sanitized_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Do not inherit credential, proxy, loader, shell, agent or Git configuration."""
    result = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "SHELL": "/bin/bash"}
    # Preserve the existing account locations. Never repurpose HOME or CODEX_HOME.
    for name in ("HOME", "CODEX_HOME"):
        value = source.get(name)
        if value:
            if not Path(value).is_absolute() or "\x00" in value:
                raise LocalWorkerPrerequisiteError("LOCAL_WORKER_INVALID_ACCOUNT_LOCATION")
            result[name] = value
    if "HOME" not in result:
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_MISSING_ACCOUNT_LOCATION")
    result.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return result


def _validate_config(config: LocalWorkerConfig) -> None:
    if config.role not in {"implementation", "review"}:
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_INVALID_ROLE")
    if type(config.timeout_seconds) is not int or not 1 <= config.timeout_seconds <= 7200:
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_INVALID_TIMEOUT")
    if type(config.max_output_bytes) is not int or not 1024 <= config.max_output_bytes <= 33554432:
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_INVALID_OUTPUT_LIMIT")
    if config.workspace != config.workspace.resolve() or not config.workspace.is_dir():
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_INVALID_WORKSPACE")
    if len(config.workspace.parts) < 4 or config.workspace == Path.home():
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_BROAD_WORKSPACE")
    if not (config.workspace / ".git").is_dir():
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_GIT_SNAPSHOT_REQUIRED")
    if config.codex_binary != CODEX_BINARY or config.bubblewrap_binary != BWRAP_BINARY:
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_UNTRUSTED_EXECUTABLE")
    if config.model is not None and (
        not isinstance(config.model, str)
        or not config.model
        or len(config.model) > 128
        or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", config.model) is None
    ):
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_INVALID_MODEL_SELECTION")
    if config.reasoning_effort not in {
        None,
        "none",
        "minimal",
        "low",
        "medium",
        "high",
        "xhigh",
        "max",
        "ultra",
    }:
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_INVALID_REASONING_SELECTION")
    # Project configuration must not execute before the tool sandbox is established.
    if next(config.workspace.rglob(".codex"), None) is not None:
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_PROJECT_CONFIG_PRESENT")
    for directory in (config.input_dir, config.dependency_env):
        if directory is not None and (
            directory != directory.resolve()
            or not directory.is_dir()
            or directory.is_relative_to(config.workspace)
            or len(directory.parts) < 4
        ):
            raise LocalWorkerPrerequisiteError("LOCAL_WORKER_INVALID_INPUT_DIRECTORY")
    if config.input_dir is not None:
        filename = "request.json" if config.role == "implementation" else "evidence.json"
        evidence = config.input_dir / filename
        if not evidence.is_file() or evidence.is_symlink():
            raise LocalWorkerPrerequisiteError("LOCAL_WORKER_INPUT_EVIDENCE_UNAVAILABLE")
    if config.dependency_env is not None and not (config.workspace / ".venv").is_dir():
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_DEPENDENCY_MOUNTPOINT_REQUIRED")
    for relative in PROTECTED_PATHS:
        candidate = config.workspace / relative
        if candidate.is_symlink() or (
            candidate.exists() and not candidate.resolve().is_relative_to(config.workspace)
        ):
            raise LocalWorkerPrerequisiteError("LOCAL_WORKER_PROTECTED_PATH_ESCAPE")


def _verify_executables(config: LocalWorkerConfig) -> None:
    for executable in (config.codex_binary, config.bubblewrap_binary, CODE_MODE_HOST_BINARY):
        try:
            metadata = executable.stat()
        except OSError:
            raise LocalWorkerPrerequisiteError("LOCAL_WORKER_EXECUTABLE_UNAVAILABLE") from None
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise LocalWorkerPrerequisiteError("LOCAL_WORKER_EXECUTABLE_NOT_PROTECTED")


def _toml_map(values: Mapping[str, str]) -> str:
    return "{" + ",".join(f"{json.dumps(k)}={json.dumps(v)}" for k, v in values.items()) + "}"


def _permission_options(config: LocalWorkerConfig, account: Path, schema: Path) -> list[str]:
    permissions = {":root": "read", "/proc": "deny", str(account): "deny"}
    if config.role == "implementation":
        permissions[str(config.workspace)] = "write"
        permissions[TOOL_TEMP_DIRECTORY] = "write"
    for relative in PROTECTED_PATHS:
        permissions[str(config.workspace / relative)] = "read"
    permissions[str(schema)] = "read"
    values = {
        "default_permissions": json.dumps(PROFILE),
        f"permissions.{PROFILE}.filesystem": _toml_map(permissions),
        f"permissions.{PROFILE}.network.enabled": "false",
        "approval_policy": '"never"',
    }
    return [value for key, item in values.items() for value in ("-c", f"{key}={item}")]


def _codex_options(config: LocalWorkerConfig, account: Path, schema: Path) -> list[str]:
    options = _permission_options(config, account, schema)
    settings = {
        "web_search": '"disabled"',
        "mcp_servers": "{}",
        "plugins": "{}",
        "hooks": "{}",
        "apps._default.enabled": "false",
        "project_doc_max_bytes": "0",
        "shell_environment_policy.inherit": '"none"',
        "shell_environment_policy.set": _toml_map(
            {
                "PATH": f"{config.workspace}/.venv/bin:{NODE_DIRECTORY}:/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "SHELL": "/bin/bash",
                "PYTHONNOUSERSITE": "1",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0",
                "TMPDIR": TOOL_TEMP_DIRECTORY,
            }
        ),
        "features.skip_host_skill_discovery": "true",
        "suppress_unstable_features_warning": "true",
        # Required by some configured models. It only brokers the already-restricted tools;
        # never fall back to an in-process host or expose plugins/MCP/host filesystem APIs.
        "features.code_mode_host": "{enabled=true,disable_in_process_fallback=true}",
    }
    for feature in DISABLED_FEATURES:
        settings[f"features.{feature}"] = "false"
    if config.model is not None:
        settings["model"] = json.dumps(config.model)
    if config.reasoning_effort is not None:
        settings["model_reasoning_effort"] = json.dumps(config.reasoning_effort)
    options.extend(value for key, item in settings.items() for value in ("-c", f"{key}={item}"))
    return options


def _outer_command(
    config: LocalWorkerConfig,
    environment: Mapping[str, str],
    schema: Path,
    *,
    native_auth: bool = True,
) -> list[str]:
    account = Path(environment.get("CODEX_HOME", str(Path(environment["HOME"]) / ".codex")))
    if account == Path("/") or account.is_relative_to(config.workspace):
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_ACCOUNT_WORKSPACE_OVERLAP")
    command = [
        str(config.bubblewrap_binary),
        "--die-with-parent",
        "--unshare-all",
        "--share-net",
        "--clearenv",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",  # noqa: S108 - new namespace's private tmpfs, not host /tmp.
        "--dir",
        TOOL_TEMP_DIRECTORY,
    ]
    for directory in RUNTIME_ROOTS:
        path = Path(directory)
        if path.is_symlink():
            command.extend(("--symlink", os.readlink(path), directory))
        elif path.is_dir():
            command.extend(("--ro-bind", directory, directory))
    for location in SYSTEM_FILES:
        if Path(location).exists():
            command.extend(("--ro-bind", location, location))
    command.extend(("--dir", environment["HOME"], "--dir", str(account)))
    # Mount only the native CLI's known auth store; never read, copy or log its contents.
    auth = account / "auth.json"
    if auth.is_symlink():
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_AUTH_STORE_SYMLINK")
    if native_auth and auth.is_file():
        command.extend(("--ro-bind", str(auth), str(auth)))
    # Native model metadata is not credential material; tools still cannot read account data.
    model_cache = account / "models_cache.json"
    if model_cache.is_symlink():
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_MODEL_CACHE_SYMLINK")
    if model_cache.is_file():
        command.extend(("--ro-bind", str(model_cache), str(model_cache)))
    workspace_mode = "--ro-bind" if config.role == "review" else "--bind"
    command.extend((workspace_mode, str(config.workspace), str(config.workspace)))
    if config.role == "implementation":
        for relative in PROTECTED_PATHS:
            path = config.workspace / relative
            if path.exists():
                command.extend(("--ro-bind", str(path), str(path)))
    if config.dependency_env is not None:
        command.extend(("--ro-bind", str(config.dependency_env), str(config.workspace / ".venv")))
    if config.input_dir is not None:
        command.extend(("--ro-bind", str(config.input_dir), "/run/redteam-input"))
        if config.role == "implementation":
            command.extend(
                (
                    "--ro-bind",
                    str(config.input_dir / "request.json"),
                    "/tmp/redteam-loop-request.json",  # noqa: S108 - private namespace mount.
                )
            )
    command.extend(("--ro-bind", str(schema), str(schema), "--chdir", str(config.workspace)))
    for key, value in environment.items():
        command.extend(("--setenv", key, value))
    return command


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


def _run_bounded(
    command: list[str],
    environment: dict[str, str],
    prompt: bytes,
    timeout_seconds: int,
    max_output_bytes: int,
) -> bytes:
    with tempfile.TemporaryFile() as input_file:
        input_file.write(prompt)
        input_file.seek(0)
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed isolated executable, never shell=True.
                command,
                stdin=input_file,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                start_new_session=True,
                close_fds=True,
            )
        except OSError:
            raise LocalWorkerPrerequisiteError("LOCAL_WORKER_START_FAILED") from None
        output = bytearray()
        total = 0
        deadline = time.monotonic() + timeout_seconds
        try:
            with selectors.DefaultSelector() as selector:
                assert process.stdout is not None and process.stderr is not None
                selector.register(process.stdout, selectors.EVENT_READ, True)
                selector.register(process.stderr, selectors.EVENT_READ, False)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise LocalWorkerTimeoutError("LOCAL_WORKER_TIMEOUT")
                    for key, _mask in selector.select(min(remaining, 0.25)):
                        block = os.read(key.fd, 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(block)
                        if total > max_output_bytes:
                            raise LocalWorkerProtocolError("LOCAL_WORKER_OUTPUT_LIMIT")
                        if key.data:
                            output.extend(block)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LocalWorkerTimeoutError("LOCAL_WORKER_TIMEOUT")
                try:
                    returncode = process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    raise LocalWorkerTimeoutError("LOCAL_WORKER_TIMEOUT") from None
                if returncode != 0:
                    raise LocalWorkerProtocolError("LOCAL_WORKER_PROCESS_FAILED")
        finally:
            # Also terminate descendants after a successful parent exit.
            _kill_group(process)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        return bytes(output)


def preflight_local_worker(config: LocalWorkerConfig) -> None:
    """Offline sandbox qualification; no prompt, auth read, model call or GitHub write."""
    _validate_config(config)
    _verify_executables(config)
    environment = sanitized_environment(os.environ)
    account = Path(environment.get("CODEX_HOME", str(Path(environment["HOME"]) / ".codex")))
    with tempfile.TemporaryDirectory(prefix="redteam-worker-preflight-") as directory:
        schema = Path(directory) / "probe.json"
        schema.write_text("{}\n", encoding="utf-8")
        mutation_probe = f".redteam-worker-probe-{uuid4().hex}"
        # Synthetic probes only: verify inaccessible parent namespace and native auth path.
        script = (
            "import errno,os,socket,sys\n"
            "for path in (sys.argv[1], '/proc/1/root' + sys.argv[1]):\n"
            " try:\n"
            "  with open(path, 'rb'): pass\n"
            " except (PermissionError, FileNotFoundError): pass\n"
            " else: raise SystemExit(20)\n"
            "try:\n"
            " s=socket.socket(); s.settimeout(0.2); s.connect(('127.0.0.1',9))\n"
            "except OSError as error:\n"
            " if error.errno not in (errno.EPERM, errno.EACCES, errno.ENETUNREACH):\n"
            "  raise SystemExit(21)\n"
            "else: raise SystemExit(22)\n"
            "for path in (sys.argv[2],sys.argv[6]):\n"
            " if not path: continue\n"
            " try:\n"
            "  with open(path, 'r+b'): pass\n"
            " except OSError as error:\n"
            "  if error.errno not in (errno.EACCES,errno.EROFS): raise\n"
            " else: raise SystemExit(23)\n"
            "for path in (sys.argv[3] + '/.git/' + sys.argv[4],):\n"
            " try:\n"
            "  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n"
            " except PermissionError: pass\n"
            " except OSError as error:\n"
            "  if error.errno != errno.EROFS: raise\n"
            " else:\n"
            "  os.close(fd); os.unlink(path); raise SystemExit(23)\n"
            "for directory in (sys.argv[3],sys.argv[7]):\n"
            " path=directory + '/' + sys.argv[4]\n"
            " try:\n"
            "  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n"
            " except OSError as error:\n"
            "  if sys.argv[5] != 'review' or error.errno not in (errno.EACCES,errno.EROFS):\n"
            "   raise\n"
            " else:\n"
            "  os.close(fd); os.unlink(path)\n"
            "  if sys.argv[5] != 'implementation': raise SystemExit(24)\n"
            "print('LOCAL_WORKER_SANDBOX_OK')\n"
        )
        command = _outer_command(config, environment, schema, native_auth=False)
        probe_path = str(account / "redteam-isolation-probe.json")
        command.extend(("--ro-bind", str(schema), probe_path))
        command.extend(
            (
                str(config.codex_binary),
                *_permission_options(config, account, schema),
                "sandbox",
                "-P",
                PROFILE,
                "--",
                "/usr/bin/python3",
                "-I",
                "-c",
                script,
                probe_path,
                str(schema),
                str(config.workspace),
                mutation_probe,
                config.role,
                (
                    "/run/redteam-input/"
                    + ("request.json" if config.role == "implementation" else "evidence.json")
                    if config.input_dir is not None
                    else ""
                ),
                TOOL_TEMP_DIRECTORY,
            )
        )
        output = _run_bounded(command, environment, b"", 30, 65536)
        if output != b"LOCAL_WORKER_SANDBOX_OK\n":
            raise LocalWorkerPrerequisiteError("LOCAL_WORKER_SANDBOX_UNQUALIFIED")


def run_local_worker(
    config: LocalWorkerConfig, prompt: str, schema: Mapping[str, Any]
) -> LocalWorkerResult:
    """Run exactly one fresh local session after non-model isolation qualification."""
    if not isinstance(prompt, str) or not prompt or len(prompt.encode()) > 524288:
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_INVALID_PROMPT")
    try:
        Draft202012Validator.check_schema(dict(schema))
    except Exception:
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_INVALID_SCHEMA") from None
    preflight_local_worker(config)
    environment = sanitized_environment(os.environ)
    account = Path(environment.get("CODEX_HOME", str(Path(environment["HOME"]) / ".codex")))
    with tempfile.TemporaryDirectory(prefix="redteam-worker-input-") as directory:
        schema_path = Path(directory) / "output-schema.json"
        schema_path.write_text(
            json.dumps(_transport_schema(schema), allow_nan=False), encoding="utf-8"
        )
        command = _outer_command(config, environment, schema_path)
        command.extend(
            (
                str(config.codex_binary),
                "exec",
                "--strict-config",
                "--ignore-user-config",
                "--ignore-rules",
                "--ephemeral",
                "--json",
                "--color",
                "never",
                "--output-schema",
                str(schema_path),
                "-C",
                str(config.workspace),
            )
        )
        command.extend(_codex_options(config, account, schema_path))
        command.append("-")
        output = _run_bounded(
            command, environment, prompt.encode(), config.timeout_seconds, config.max_output_bytes
        )
    result = parse_worker_output(output)
    if not Draft202012Validator(dict(schema)).is_valid(result.final_json):
        raise LocalWorkerProtocolError("LOCAL_WORKER_SCHEMA_REJECTED")
    return result


def run_local_validation(config: LocalWorkerConfig, phase: str) -> LocalValidationResult:
    """Run the fixed phase gate without a model, host auth, hooks or tool networking."""
    _validate_config(config)
    _verify_executables(config)
    if re.fullmatch(r"phase-(?:0a|0b|0c|[1-5])", phase) is None:
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_INVALID_PHASE")
    if config.role != "implementation" or config.dependency_env is None:
        raise LocalWorkerPrerequisiteError("LOCAL_WORKER_VALIDATION_REQUIRES_DEPENDENCIES")
    environment = sanitized_environment(os.environ)
    with tempfile.TemporaryDirectory(prefix="redteam-validation-") as directory:
        marker = Path(directory) / "validation-input.json"
        marker.write_text("{}\n", encoding="utf-8")
        command = _outer_command(config, environment, marker, native_auth=False)
        command.remove("--share-net")
        # Untrusted tests cannot read native CLI auth, parent /proc, gh config or sockets:
        # these are absent from the outer namespace, which also has no network devices.
        command.extend(
            (
                "--setenv",
                "PATH",
                f"{config.workspace}/.venv/bin:{NODE_DIRECTORY}:/usr/bin:/bin",
                "--",
                "/bin/bash",
                "scripts/ci/run_phase_gate.sh",
                phase,
            )
        )
        output = _run_bounded(
            command, environment, b"", config.timeout_seconds, config.max_output_bytes
        )
    try:
        stdout = output.decode("utf-8", errors="strict")
    except UnicodeError:
        raise LocalWorkerProtocolError("LOCAL_WORKER_INVALID_VALIDATION_OUTPUT") from None
    if not stdout.rstrip().endswith(f"PHASE_GATE={phase} PASS"):
        raise LocalWorkerProtocolError("LOCAL_WORKER_PHASE_GATE_INCOMPLETE")
    return LocalValidationResult(stdout, hashlib.sha256(output).hexdigest())
