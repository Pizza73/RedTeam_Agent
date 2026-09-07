"""Typed execution-scope, target-reference and normalized-target models.

Scope is a set of typed rules, never free-form strings (SystemDesign §21).
Data-access resources are controlled separately by the data-access policy and
must not be mixed into execution scope.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from redteam_agent.models.base import StrictImmutableBoundaryModel

# --- Execution scope rules ------------------------------------------------


class NetworkScopeRule(StrictImmutableBoundaryModel):
    type: Literal["network"]
    cidrs: tuple[str, ...] = Field(min_length=1)
    ports: tuple[int, ...] | None = None
    protocols: tuple[str, ...] | None = None


class HostnameScopeRule(StrictImmutableBoundaryModel):
    type: Literal["hostname"]
    hostname: str
    ports: tuple[int, ...] | None = None


class DomainScopeRule(StrictImmutableBoundaryModel):
    type: Literal["domain"]
    domain: str
    include_subdomains: bool = False


class UrlScopeRule(StrictImmutableBoundaryModel):
    type: Literal["url"]
    scheme: Literal["http", "https"]
    hostname: str
    port: int | None = None
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


# --- Target references (planner-proposed candidates) ----------------------


class IpTargetReference(StrictImmutableBoundaryModel):
    type: Literal["ip"]
    address: str = Field(min_length=1)


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
    | NamedTargetReference
    | HostTargetReference
    | SessionTargetReference
    | RemoteFilesystemTargetReference,
    Field(discriminator="type"),
]


# --- Normalized target (policy-resolved) ----------------------------------


class NormalizedTarget(StrictImmutableBoundaryModel):
    type: Literal[
        "ip",
        "hostname",
        "domain",
        "url",
        "host",
        "session",
        "remote_filesystem",
    ]
    canonical_value: str = Field(min_length=1)
    host_ref: str | None = None
    port: int | None = None
    protocol: str | None = None
    resolved_addresses: tuple[str, ...] = ()
    source: Literal["plan", "argument", "session", "dns", "redirect"]
