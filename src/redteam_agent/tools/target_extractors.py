"""Closed, trusted registry of Phase 0A target extractors."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from redteam_agent.errors import TargetExtractorResolutionError
from redteam_agent.models.plans import ExecutionPlanProposal
from redteam_agent.models.scope import (
    CidrTargetReference,
    HostTargetReference,
    IpTargetReference,
    SessionTargetReference,
    TargetReference,
)
from redteam_agent.models.tools import TargetExtractorId, ToolDefinition

Extractor = Callable[[ExecutionPlanProposal, ToolDefinition], tuple[TargetReference, ...]]


def _argument_values(proposal: ExecutionPlanProposal, tool: ToolDefinition) -> tuple[Any, ...]:
    schema = tool.parameter_schema.to_dict()
    fields = schema.get("x-redteam-target-fields", [])
    if not isinstance(fields, list) or any(not isinstance(field, str) for field in fields):
        raise TargetExtractorResolutionError("invalid trusted target-field declaration")
    arguments = proposal.arguments.to_dict()
    values: list[Any] = []
    for field in fields:
        if field not in arguments:
            continue
        value = arguments[field]
        values.extend(value if isinstance(value, list) else [value])
    return tuple(values)


def _network(proposal: ExecutionPlanProposal, tool: ToolDefinition) -> tuple[TargetReference, ...]:
    schema = tool.parameter_schema.to_dict()
    arguments = proposal.arguments.to_dict()
    port_field = schema.get("x-redteam-port-field")
    protocol_field = schema.get("x-redteam-protocol-field")
    requires_port = schema.get("x-redteam-requires-port", False)
    requires_protocol = schema.get("x-redteam-requires-protocol", False)
    if port_field is not None and not isinstance(port_field, str):
        raise TargetExtractorResolutionError("invalid trusted port-field declaration")
    if protocol_field is not None and not isinstance(protocol_field, str):
        raise TargetExtractorResolutionError("invalid trusted protocol-field declaration")
    if not isinstance(requires_port, bool) or not isinstance(requires_protocol, bool):
        raise TargetExtractorResolutionError("invalid endpoint requirement declaration")
    port = arguments.get(port_field) if port_field is not None else None
    protocol = arguments.get(protocol_field) if protocol_field is not None else None
    if port is not None and (not isinstance(port, int) or isinstance(port, bool)):
        raise TargetExtractorResolutionError("network port must be an integer")
    if protocol is not None:
        if not isinstance(protocol, str) or protocol.lower() not in {"tcp", "udp"}:
            raise TargetExtractorResolutionError("network protocol must be tcp or udp")
        protocol = protocol.lower()
    if requires_port and port is None:
        raise TargetExtractorResolutionError("required network port was not extracted")
    if requires_protocol and protocol is None:
        raise TargetExtractorResolutionError("required network protocol was not extracted")

    result: list[TargetReference] = []
    for target in proposal.requested_targets:
        if not isinstance(target, (IpTargetReference, CidrTargetReference)):
            raise TargetExtractorResolutionError("network extractor received a non-network target")
        # Explicit target endpoint data is authoritative.  Trusted argument metadata
        # fills it only when the target did not carry that dimension.
        result.append(
            target.model_copy(
                update={
                    "port": target.port if target.port is not None else port,
                    "protocol": target.protocol if target.protocol is not None else protocol,
                }
            )
        )
    for value in _argument_values(proposal, tool):
        if not isinstance(value, str):
            raise TargetExtractorResolutionError("network argument target must be a string")
        if "/" in value:
            result.append(
                CidrTargetReference(type="cidr", cidr=value, port=port, protocol=protocol)
            )
        else:
            result.append(
                IpTargetReference(type="ip", address=value, port=port, protocol=protocol)
            )
    return tuple(result)


def _host(proposal: ExecutionPlanProposal, tool: ToolDefinition) -> tuple[TargetReference, ...]:
    result: list[TargetReference] = []
    for target in proposal.requested_targets:
        if not isinstance(target, HostTargetReference):
            raise TargetExtractorResolutionError("host extractor received a non-host target")
        result.append(target)
    for value in _argument_values(proposal, tool):
        if not isinstance(value, str):
            raise TargetExtractorResolutionError("host target must be a string")
        result.append(HostTargetReference(type="host", host_id=value))
    return tuple(result)


def _session(proposal: ExecutionPlanProposal, tool: ToolDefinition) -> tuple[TargetReference, ...]:
    result: list[TargetReference] = []
    for target in proposal.requested_targets:
        if not isinstance(target, SessionTargetReference):
            raise TargetExtractorResolutionError("session extractor received a non-session target")
        result.append(target)
    for value in _argument_values(proposal, tool):
        if not isinstance(value, str):
            raise TargetExtractorResolutionError("session target must be a string")
        result.append(SessionTargetReference(type="session", session_id=value))
    return tuple(result)


def _artifact(proposal: ExecutionPlanProposal, tool: ToolDefinition) -> tuple[TargetReference, ...]:
    del proposal, tool
    raise TargetExtractorResolutionError(
        "artifact_target_v1 is reserved for Data Access and is not an execution-scope extractor"
    )


class TrustedTargetExtractorRegistry:
    """No dynamic import, expressions, lambdas or plugin-provided code."""

    def __init__(self) -> None:
        self._extractors: dict[str, Extractor] = {
            "network_target_v1": _network,
            "session_target_v1": _session,
            "host_target_v1": _host,
            "artifact_target_v1": _artifact,
        }

    @property
    def registered_ids(self) -> frozenset[str]:
        return frozenset(self._extractors)

    def resolve(self, extractor_id: str) -> Extractor:
        try:
            return self._extractors[extractor_id]
        except KeyError as exc:
            raise TargetExtractorResolutionError(
                f"target extractor is not trusted: {extractor_id}"
            ) from exc

    def extract(
        self, extractor_id: TargetExtractorId, proposal: ExecutionPlanProposal, tool: ToolDefinition
    ) -> tuple[TargetReference, ...]:
        return self.resolve(extractor_id)(proposal, tool)
