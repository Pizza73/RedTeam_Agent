"""Typed execution scope, target and data-access models."""

from __future__ import annotations

import ipaddress
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from .base import StrictImmutableBoundaryModel


class NetworkScopeRule(StrictImmutableBoundaryModel):
    type: Literal["network"]
    cidrs: tuple[str, ...] = Field(min_length=1)
    ports: tuple[int, ...] | None = None
    protocols: tuple[str, ...] | None = None

    @field_validator("cidrs")
    @classmethod
    def canonical_cidrs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        networks: list[str] = []
        for item in value:
            try:
                networks.append(str(ipaddress.ip_network(item, strict=False)))
            except ValueError as exc:
                raise ValueError(f"invalid network scope: {item}") from exc
        if len(set(networks)) != len(networks):
            raise ValueError("duplicate network scope")
        return tuple(sorted(networks, key=lambda item: (ipaddress.ip_network(item).version, item)))

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, value: tuple[int, ...] | None) -> tuple[int, ...] | None:
        if value is not None and any(port < 1 or port > 65535 for port in value):
            raise ValueError("port must be between 1 and 65535")
        return tuple(sorted(set(value))) if value is not None else None

    @field_validator("protocols")
    @classmethod
    def canonical_protocols(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if value is None:
            return None
        normalized = tuple(sorted({item.lower() for item in value}))
        if not normalized or any(item not in {"tcp", "udp"} for item in normalized):
            raise ValueError("network protocols must be tcp or udp")
        return normalized


class HostnameScopeRule(StrictImmutableBoundaryModel):
    type: Literal["hostname"]
    hostname: str = Field(min_length=1)
    ports: tuple[int, ...] | None = None


class DomainScopeRule(StrictImmutableBoundaryModel):
    type: Literal["domain"]
    domain: str = Field(min_length=1)
    include_subdomains: bool = False


class UrlScopeRule(StrictImmutableBoundaryModel):
    type: Literal["url"]
    scheme: Literal["http", "https"]
    hostname: str = Field(min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    path_prefix: str = "/"


class HostScopeRule(StrictImmutableBoundaryModel):
    type: Literal["host"]
    host_id: str = Field(min_length=1)


class SessionScopeRule(StrictImmutableBoundaryModel):
    type: Literal["session"]
    session_id: str = Field(min_length=1)


class RemoteFilesystemScopeRule(StrictImmutableBoundaryModel):
    type: Literal["remote_filesystem"]
    host_ref: str = Field(min_length=1)
    path_prefix: str = Field(min_length=1)


ExecutionScopeRule = Annotated[
    NetworkScopeRule
    | HostnameScopeRule
    | DomainScopeRule
    | UrlScopeRule
    | HostScopeRule
    | SessionScopeRule
    | RemoteFilesystemScopeRule,
    Field(discriminator="type"),
]


class IpTargetReference(StrictImmutableBoundaryModel):
    type: Literal["ip"]
    address: str = Field(min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["tcp", "udp"] | None = None


class CidrTargetReference(StrictImmutableBoundaryModel):
    type: Literal["cidr"]
    cidr: str = Field(min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["tcp", "udp"] | None = None


class NamedTargetReference(StrictImmutableBoundaryModel):
    type: Literal["hostname", "domain", "url"]
    value: str = Field(min_length=1)


class HostTargetReference(StrictImmutableBoundaryModel):
    type: Literal["host"]
    host_id: str = Field(min_length=1)


class SessionTargetReference(StrictImmutableBoundaryModel):
    type: Literal["session"]
    session_id: str = Field(min_length=1)


class RemoteFilesystemTargetReference(StrictImmutableBoundaryModel):
    type: Literal["remote_filesystem"]
    host_ref: str = Field(min_length=1)
    path: str = Field(min_length=1)


TargetReference = Annotated[
    IpTargetReference
    | CidrTargetReference
    | NamedTargetReference
    | HostTargetReference
    | SessionTargetReference
    | RemoteFilesystemTargetReference,
    Field(discriminator="type"),
]


class NormalizedTarget(StrictImmutableBoundaryModel):
    type: Literal[
        "ip", "cidr", "hostname", "domain", "url", "host", "session", "remote_filesystem"
    ]
    canonical_value: str = Field(min_length=1)
    host_ref: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["tcp", "udp"] | None = None
    resolved_addresses: tuple[str, ...] = ()
    source: Literal["plan", "argument", "session", "dns", "redirect"]


DataAccessOperation = Literal["read", "write", "export", "resolve"]
DataResourceType = Literal[
    "artifact", "secret_reference", "local_artifact", "report", "internal_knowledge"
]


class DataAccessRule(StrictImmutableBoundaryModel):
    resource_type: DataResourceType
    resource_pattern: str = Field(min_length=1)
    operations: frozenset[DataAccessOperation] = Field(min_length=1)

    @field_validator("resource_pattern")
    @classmethod
    def fixed_pattern_grammar(cls, value: str) -> str:
        if any(token in value for token in ("[", "]", "(", ")", "?", "+", "|", "\\")):
            raise ValueError("resource pattern is not a regular expression")
        if "*" in value and (not value.endswith("*") or value.count("*") != 1):
            raise ValueError("only a single trailing '*' prefix match is implemented")
        return value


class DataAccessPolicy(StrictImmutableBoundaryModel):
    allowed: tuple[DataAccessRule, ...]
    prohibited: tuple[DataAccessRule, ...]


class ApprovalPolicy(StrictImmutableBoundaryModel):
    require_for_risk: frozenset[Literal["read", "low", "medium", "high"]]
    require_for_side_effect: frozenset[Literal["read_only", "state_change", "destructive"]]
    approval_ttl_seconds: int = Field(gt=0)
    count_approval_wait_in_runtime: bool


class ResourceAccessRequest(StrictImmutableBoundaryModel):
    resource_type: DataResourceType
    resource_id: str = Field(min_length=1)
    operations: frozenset[DataAccessOperation] = Field(min_length=1)

    @model_validator(mode="after")
    def planner_context_cannot_resolve(self) -> ResourceAccessRequest:
        return self
