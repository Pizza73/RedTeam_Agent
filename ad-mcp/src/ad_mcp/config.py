"""Fail-closed settings and scope loading."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, field_validator, model_validator

from ad_mcp.errors import ConfigurationError
from ad_mcp.models import StrictModel


class ScopeConfig(StrictModel):
    schema_version: Literal["ad-mcp-scope-v1"]
    cidrs: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()

    @model_validator(mode="after")
    def nonempty(self) -> ScopeConfig:
        if not (self.cidrs or self.domains or self.hosts):
            raise ValueError("scope must not be empty")
        return self


class Settings(StrictModel):
    schema_version: Literal["ad-mcp-settings-v1"]
    client_id: str = Field(min_length=1, max_length=128)
    workspace_root: Path
    raw_root: Path
    state_db: Path
    audit_log: Path
    binary_paths: dict[str, Path]
    binary_sha256: dict[str, str] = Field(default_factory=dict)
    resources: dict[str, Path] = Field(default_factory=dict)
    enabled_operations: tuple[str, ...]
    intrusive_enabled: bool = False
    max_concurrent_jobs: int = Field(default=2, ge=1, le=32)
    max_targets: int = Field(default=16, ge=1, le=256)
    retention_hours: int = Field(default=24, ge=1, le=720)
    transport: Literal["stdio"] = "stdio"
    remote_transport: Literal["disabled"] = "disabled"

    @field_validator("workspace_root", "raw_root", "state_db", "audit_log")
    @classmethod
    def absolute_paths(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("runtime paths must be absolute")
        return value

    @model_validator(mode="after")
    def paths_are_contained(self) -> Settings:
        root = self.workspace_root.resolve(strict=False)
        for value in (self.raw_root, self.state_db, self.audit_log):
            resolved = value.resolve(strict=False)
            if resolved != root and root not in resolved.parents:
                raise ValueError("runtime paths must be under workspace_root")
        for binary_id, path in self.binary_paths.items():
            if not binary_id or not path.is_absolute():
                raise ValueError("binary paths must be named absolute paths")
        if len(self.enabled_operations) != len(set(self.enabled_operations)):
            raise ValueError("enabled operation IDs must be unique")
        if any(
            re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in self.binary_sha256.values()
        ):
            raise ValueError("binary digests must be lowercase SHA-256 values")
        for resource_id, path in self.resources.items():
            if not resource_id or not path.is_absolute():
                raise ValueError("resources must be named absolute paths")
            resolved = path.resolve(strict=False)
            if root not in resolved.parents:
                raise ValueError("resources must be under workspace_root")
        return self


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError("CONFIG_READ_FAILED") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("CONFIG_ROOT_INVALID")
    return value


def load_settings(path: Path) -> Settings:
    try:
        settings = Settings.model_validate(_load_yaml(path))
    except ValueError as exc:
        raise ConfigurationError("SETTINGS_INVALID") from exc
    settings.workspace_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    settings.raw_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for parent in (settings.state_db.parent, settings.audit_log.parent):
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return settings


def load_scope(path: Path) -> ScopeConfig:
    try:
        return ScopeConfig.model_validate(_load_yaml(path))
    except ValueError as exc:
        raise ConfigurationError("SCOPE_INVALID") from exc


def load_project_token() -> str:
    token = os.environ.get("AD_MCP_PROJECT_TOKEN", "")
    if len(token) < 32:
        raise ConfigurationError("PROJECT_TOKEN_MISSING")
    return token
