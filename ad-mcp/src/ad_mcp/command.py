"""Strict argument validation and shell-free command construction."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from ad_mcp.auth import EphemeralSecret
from ad_mcp.config import Settings
from ad_mcp.errors import ConfigurationError, ValidationError
from ad_mcp.models import (
    CommandPlan,
    ParameterKind,
    ProjectAuthorization,
    Risk,
    SecretReference,
    ToolCall,
    ToolDefinition,
)
from ad_mcp.scope import ScopePolicy


class BuiltCommand:
    __slots__ = ("argv", "plan")

    def __init__(self, argv: tuple[str, ...], plan: CommandPlan) -> None:
        self.argv = argv
        self.plan = plan


class CommandBuilder:
    def __init__(self, settings: Settings, scope: ScopePolicy) -> None:
        self._settings = settings
        self._scope = scope

    def build(
        self,
        tool: ToolDefinition,
        call: ToolCall,
        auth: ProjectAuthorization,
        secrets: tuple[EphemeralSecret, ...],
    ) -> BuiltCommand:
        targets = self._scope.authorize_targets(
            call.targets,
            required=tool.network_target_required,
            maximum=self._settings.max_targets,
        )
        domain = self._scope.authorize_domain(call.domain)
        timeout = tool.default_timeout_seconds
        values = dict(call.parameters)
        if domain is not None:
            values["domain"] = domain
        if call.username is not None:
            values["username"] = call.username
        if "timeout_seconds" in values:
            timeout_value = values.pop("timeout_seconds")
            if type(timeout_value) is not int or not 1 <= timeout_value <= 86_400:
                raise ValidationError("TIMEOUT_INVALID")
            timeout = timeout_value
        allowed = {spec.name for spec in tool.parameters}
        if set(values) - allowed:
            raise ValidationError("UNKNOWN_PARAMETER")
        if not call.dry_run:
            self._authorize_execution(tool, auth)
        executable = self._executable(tool, dry_run=call.dry_run)
        argv = [executable, *tool.argv_prefix]
        redacted = list(argv)
        for spec in tool.parameters:
            if spec.name == "timeout_seconds":
                continue
            value = values.get(spec.name)
            if value is None:
                if spec.required:
                    raise ValidationError("REQUIRED_PARAMETER_MISSING")
                continue
            rendered, hidden = self._render_parameter(spec, value, secrets, call.dry_run)
            if spec.flag is not None:
                argv.append(spec.flag)
                redacted.append(spec.flag)
            if spec.kind is ParameterKind.BOOLEAN:
                continue
            argv.append(rendered)
            redacted.append(hidden)
        argv.extend(targets)
        redacted.extend(targets)
        return BuiltCommand(
            tuple(argv),
            CommandPlan(
                operation_id=tool.operation_id,
                executable=executable,
                redacted_argv=tuple(redacted),
                targets=targets,
                risk=tool.risk,
                timeout_seconds=timeout,
                max_output_bytes=tool.max_output_bytes,
            ),
        )

    def _authorize_execution(self, tool: ToolDefinition, auth: ProjectAuthorization) -> None:
        if tool.operation_id not in self._settings.enabled_operations:
            raise ValidationError("OPERATION_DISABLED")
        if tool.risk is Risk.UNCLASSIFIED:
            raise ValidationError("RISK_CLASSIFICATION_PENDING")
        if tool.risk is Risk.INTRUSIVE:
            if not self._settings.intrusive_enabled:
                raise ValidationError("INTRUSIVE_DISABLED")
            if auth.approval_id is None:
                raise ValidationError("INTRUSIVE_APPROVAL_REQUIRED")
        if tool.remote_windows and self._settings.remote_transport == "disabled":
            raise ConfigurationError("REMOTE_TRANSPORT_UNCONFIGURED")

    def _executable(self, tool: ToolDefinition, *, dry_run: bool) -> str:
        if tool.remote_windows:
            return f"payload:{tool.binary_id}"
        path = self._settings.binary_paths.get(tool.binary_id)
        if path is None:
            if dry_run:
                return f"binary:{tool.binary_id}"
            raise ConfigurationError("BINARY_NOT_CONFIGURED")
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise ConfigurationError("BINARY_NOT_FOUND") from exc
        if resolved != path or not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise ConfigurationError("BINARY_IDENTITY_INVALID")
        expected = self._settings.binary_sha256.get(tool.binary_id)
        if expected is None:
            raise ConfigurationError("BINARY_DIGEST_MISSING")
        digest = _file_sha256(resolved)
        if digest != expected:
            raise ConfigurationError("BINARY_DIGEST_MISMATCH")
        return str(resolved)

    def _render_parameter(
        self,
        spec: object,
        value: object,
        secrets: tuple[EphemeralSecret, ...],
        dry_run: bool,
    ) -> tuple[str, str]:
        from ad_mcp.models import ParameterSpec

        assert isinstance(spec, ParameterSpec)
        if spec.kind is ParameterKind.SECRET:
            try:
                reference = SecretReference.model_validate(value)
            except ValueError as exc:
                raise ValidationError("SECRET_REFERENCE_INVALID") from exc
            hidden = f"<secret:{reference.secret_version_id}>"
            if dry_run:
                return hidden, hidden
            matching = [
                item
                for item in secrets
                if item.argument_name == spec.name
                and item.secret_version_id == reference.secret_version_id
            ]
            if len(matching) != 1:
                raise ValidationError("SECRET_BINDING_MISMATCH")
            try:
                rendered = bytes(matching[0].material).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValidationError("SECRET_ENCODING_INVALID") from exc
            _validate_scalar(rendered, None)
            return rendered, hidden
        if spec.kind is ParameterKind.RESOURCE:
            if not isinstance(value, str):
                raise ValidationError("RESOURCE_INVALID")
            path = self._resource_path(value)
            return str(path), str(path)
        if spec.kind is ParameterKind.INTEGER:
            if type(value) is not int:
                raise ValidationError("INTEGER_PARAMETER_INVALID")
            if spec.minimum is not None and value < spec.minimum:
                raise ValidationError("INTEGER_PARAMETER_INVALID")
            if spec.maximum is not None and value > spec.maximum:
                raise ValidationError("INTEGER_PARAMETER_INVALID")
            return str(value), str(value)
        if spec.kind is ParameterKind.BOOLEAN:
            if type(value) is not bool:
                raise ValidationError("BOOLEAN_PARAMETER_INVALID")
            if value is not True:
                raise ValidationError("BOOLEAN_PARAMETER_FALSE_UNSUPPORTED")
            return "", ""
        if not isinstance(value, str):
            raise ValidationError("STRING_PARAMETER_INVALID")
        if spec.kind is ParameterKind.ENUM and value not in spec.choices:
            raise ValidationError("ENUM_PARAMETER_INVALID")
        _validate_scalar(value, spec.pattern)
        return value, "<redacted>" if spec.sensitive else value

    def _resource_path(self, value: str) -> Path:
        if not value or len(value) > 256 or value.startswith("-"):
            raise ValidationError("RESOURCE_ID_INVALID")
        configured = self._settings.resources.get(value)
        if configured is None:
            raise ValidationError("RESOURCE_NOT_APPROVED")
        root = self._settings.workspace_root.resolve(strict=True)
        try:
            relative = configured.relative_to(root)
        except ValueError as exc:
            raise ValidationError("RESOURCE_PATH_INVALID") from exc
        candidate = configured
        current = root
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ValidationError("RESOURCE_PATH_INVALID")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise ValidationError("RESOURCE_NOT_FOUND") from exc
        if root not in resolved.parents or not resolved.is_file():
            raise ValidationError("RESOURCE_PATH_INVALID")
        return resolved


def _validate_scalar(value: str, pattern: str | None) -> None:
    invalid_character = any(character in value for character in "\x00\r\n")
    if not value or len(value) > 4096 or value.startswith("-") or invalid_character:
        raise ValidationError("STRING_PARAMETER_INVALID")
    if pattern is not None and re.fullmatch(pattern, value) is None:
        raise ValidationError("STRING_PARAMETER_INVALID")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
