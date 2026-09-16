"""Strict wire contracts for the local operator UI.

UI drafts are deliberately non-authoritative.  They can be reviewed and persisted,
but never become a MissionRevision, PolicyDecision, or execution authority through
this boundary.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.models.base import StrictBoundaryModel, StrictImmutableBoundaryModel


class MissionDraftTarget(StrictImmutableBoundaryModel):
    id: str = Field(min_length=1, max_length=100)
    type: Literal[
        "network", "host", "session", "hostname", "domain", "url", "remote_filesystem", "other"
    ]
    value: str = Field(min_length=1, max_length=2048)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["tcp", "udp"] | None

    @model_validator(mode="after")
    def _network_fields_are_bound(self) -> MissionDraftTarget:
        if self.type == "network" and self.protocol is None:
            raise ValueError("network target requires protocol")
        if self.type != "network" and (self.port is not None or self.protocol is not None):
            raise ValueError("non-network target cannot carry port or protocol")
        return self


class MissionDraftInput(StrictImmutableBoundaryModel):
    name: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=10, max_length=4000)
    authorizationReference: str = Field(min_length=1, max_length=500)
    validUntil: datetime
    targets: tuple[MissionDraftTarget, ...] = Field(min_length=1, max_length=100)
    successType: Literal[
        "session_exists", "windows_privilege", "ad_membership", "linux_root", "evidence", "artifact", "other"
    ]
    successValue: str = Field(min_length=1, max_length=4000)
    maxIterations: int = Field(gt=0, le=10_000)
    maxRuntimeMinutes: int = Field(gt=0, le=7 * 24 * 60)
    approvalRisk: Literal["low", "medium", "high"]

    @model_validator(mode="after")
    def _valid_until_is_zoned(self) -> MissionDraftInput:
        if self.validUntil.tzinfo is None or self.validUntil.utcoffset() is None:
            raise ValueError("validUntil requires an explicit timezone")
        return self


class ProviderOperationDraft(StrictImmutableBoundaryModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=200)
    source: Literal["impacket_mcp", "offline_analysis"]
    state: Literal["allowed", "approval_required", "disabled"]
    arbitraryArguments: Literal[False]


class C2Draft(StrictImmutableBoundaryModel):
    providerId: Literal["none", "tuoni"]
    registryReference: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _reference_matches_selection(self) -> C2Draft:
        if self.providerId == "none" and self.registryReference is not None:
            raise ValueError("unselected C2 cannot carry a registry reference")
        if self.providerId == "tuoni" and self.registryReference is None:
            raise ValueError("Tuoni selection requires a registry reference")
        return self


class ProviderPolicyDraftInput(StrictImmutableBoundaryModel):
    missionRevision: int = Field(ge=1)
    c2: C2Draft
    enabledMcpServers: tuple[Literal["impacket_mcp"], ...]
    operations: tuple[ProviderOperationDraft, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def _closed_provider_set(self) -> ProviderPolicyDraftInput:
        if len(set(self.enabledMcpServers)) != len(self.enabledMcpServers):
            raise ValueError("MCP server IDs must be unique")
        if "impacket_mcp" not in self.enabledMcpServers:
            raise ValueError("Impacket MCP is required by the current Phase 5 runtime")
        ids = tuple(operation.id for operation in self.operations)
        if len(set(ids)) != len(ids):
            raise ValueError("operation IDs must be unique")
        registered = {
            "impacket.smb.negotiate",
            "impacket.smb.authenticate",
            "impacket.smb.list_shares",
            "impacket.rpc.endpoint_map",
        }
        if set(ids) != registered or any(operation.source != "impacket_mcp" for operation in self.operations):
            raise ValueError("provider draft must contain the exact registered Impacket operation set")
        return self


class ApprovalDecisionInput(StrictImmutableBoundaryModel):
    decision: Literal["approved", "rejected"]
    presentationDigest: str = Field(min_length=1, max_length=256)


class CandidateSelectionInput(StrictImmutableBoundaryModel):
    candidateId: str = Field(min_length=1, max_length=200)


class VllmConfigInput(StrictImmutableBoundaryModel):
    baseUrl: str = Field(min_length=1, max_length=2048)
    modelName: str = Field(min_length=1, max_length=300)
    wireApi: Literal["chat_completions"]
    structuredOutputMode: Literal["native", "tool_output"]

    @model_validator(mode="after")
    def _http_url_only(self) -> VllmConfigInput:
        parsed = urlsplit(self.baseUrl)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None or parsed.username is not None:
            raise ValueError("baseUrl must use HTTP or HTTPS")
        return self


class StoredDraft(StrictImmutableBoundaryModel):
    draftId: str = Field(min_length=1)
    savedAt: datetime
    draft: CanonicalJsonObject


class ApiErrorBody(StrictBoundaryModel):
    error: str = Field(min_length=1)
    code: str = Field(min_length=1)
