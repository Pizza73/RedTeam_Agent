"""Trusted target extractor registry (SystemDesign §20 / §22, B-02).

Target extraction is part of the authorization kernel. Extractors are resolved
by id from a fixed, in-code registry (no dynamic import, no plugin-supplied
extractors). Critically, an extractor does not trust the planner's
``requested_targets``: it validates the tool arguments against a **closed**
argument schema (``extra='forbid'``) and independently enumerates every
destination, port, protocol and session those arguments influence. Because the
argument schema is closed, an out-of-scope destination cannot hide in an
undeclared field. ``requested_targets`` are unioned in as extra checks, never as
a substitute. A tool with no external target declares that by contract; an
extraction that yields nothing where a target is required is a fail-closed
error, never an empty-set success.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import ValidationError

from redteam_agent.canonical.immutable import thaw
from redteam_agent.canonical.json_boundary import CanonicalJsonObject
from redteam_agent.errors import TargetExtractorResolutionError
from redteam_agent.models.base import StrictBoundaryModel
from redteam_agent.policy.scope_models import NormalizedTarget, TargetReference
from redteam_agent.policy.target_normalizer import canonicalize_ip, normalize_port, normalize_protocol


@dataclass(frozen=True)
class TargetExtractionInput:
    requested_targets: tuple[TargetReference, ...]
    arguments: CanonicalJsonObject
    session_id: str | None


# --- Closed argument contracts (one per extractor) ------------------------


class _NetworkArgs(StrictBoundaryModel):
    """Closed argument contract for ``network_target_v1``.

    Every field is accounted for: ``destinations`` carry targets; ``port`` and
    ``protocol`` qualify them; ``timeout_seconds`` is an explicitly declared
    non-destination field. Any other field is rejected, so a destination cannot
    hide in an undeclared argument.
    """

    destinations: tuple[str, ...]
    port: int | None = None
    protocol: str | None = None
    timeout_seconds: int | None = None
    # A declared, non-destination secret reference field. Declaring it keeps the
    # contract closed (no undeclared field) while allowing a secret argument.
    credential: CanonicalJsonObject | None = None


class _HostArgs(StrictBoundaryModel):
    host_ids: tuple[str, ...]
    timeout_seconds: int | None = None


class _SessionArgs(StrictBoundaryModel):
    session_ids: tuple[str, ...] = ()
    timeout_seconds: int | None = None


class _ArtifactArgs(StrictBoundaryModel):
    """Pure analysis tools may reference artifact ids only, never destinations."""

    artifact_ids: tuple[str, ...] = ()
    report_ids: tuple[str, ...] = ()


def _parse_args(model: type[StrictBoundaryModel], arguments: CanonicalJsonObject) -> StrictBoundaryModel:
    # Validate through the JSON-wire path so a JSON array satisfies a tuple
    # field, while strict mode still rejects unknown fields and numeric-string
    # coercion. Content-free error message (no argument values leak).
    try:
        return model.model_validate_json(json.dumps(thaw(arguments)))
    except ValidationError as exc:
        raise TargetExtractorResolutionError(
            f"tool arguments do not satisfy the closed extractor contract ({len(exc.errors())} error(s))"
        ) from None


def _dedupe(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen


def _extract_network(data: TargetExtractionInput) -> tuple[NormalizedTarget, ...]:
    args = _parse_args(_NetworkArgs, data.arguments)
    assert isinstance(args, _NetworkArgs)
    port = normalize_port(args.port) if args.port is not None else None
    protocol = normalize_protocol(args.protocol) if args.protocol is not None else None

    addresses = list(args.destinations)
    for reference in data.requested_targets:
        if reference.type != "ip":
            raise TargetExtractorResolutionError(
                f"network_target_v1 cannot handle requested target type {reference.type!r}"
            )
        addresses.append(reference.address)

    canonical_addresses = _dedupe([canonicalize_ip(address) for address in addresses])
    if not canonical_addresses:
        raise TargetExtractorResolutionError("network_target_v1 resolved no destinations")
    return tuple(
        NormalizedTarget(
            type="ip",
            canonical_value=address,
            port=port,
            protocol=protocol,
            resolved_addresses=(address,),
            source="argument",
        )
        for address in canonical_addresses
    )


def _extract_host(data: TargetExtractionInput) -> tuple[NormalizedTarget, ...]:
    args = _parse_args(_HostArgs, data.arguments)
    assert isinstance(args, _HostArgs)
    host_ids = list(args.host_ids)
    for reference in data.requested_targets:
        if reference.type != "host":
            raise TargetExtractorResolutionError(
                f"host_target_v1 cannot handle requested target type {reference.type!r}"
            )
        host_ids.append(reference.host_id)
    unique = _dedupe(host_ids)
    if not unique:
        raise TargetExtractorResolutionError("host_target_v1 resolved no hosts")
    return tuple(NormalizedTarget(type="host", canonical_value=host_id, source="argument") for host_id in unique)


def _extract_session(data: TargetExtractionInput) -> tuple[NormalizedTarget, ...]:
    args = _parse_args(_SessionArgs, data.arguments)
    assert isinstance(args, _SessionArgs)
    session_ids = list(args.session_ids)
    for reference in data.requested_targets:
        if reference.type != "session":
            raise TargetExtractorResolutionError(
                f"session_target_v1 cannot handle requested target type {reference.type!r}"
            )
        session_ids.append(reference.session_id)
    if data.session_id is not None:
        session_ids.append(data.session_id)
    unique = _dedupe(session_ids)
    if not unique:
        raise TargetExtractorResolutionError("session_target_v1 resolved no session target")
    return tuple(
        NormalizedTarget(type="session", canonical_value=session_id, source="session") for session_id in unique
    )


def _extract_artifact(data: TargetExtractionInput) -> tuple[NormalizedTarget, ...]:
    # Validates that arguments contain only artifact/report references; a closed
    # contract with no destination fields means analysis tools cannot hide one.
    _parse_args(_ArtifactArgs, data.arguments)
    if data.requested_targets:
        raise TargetExtractorResolutionError("artifact_target_v1 does not accept external targets")
    return ()


_Extractor = Callable[[TargetExtractionInput], tuple[NormalizedTarget, ...]]

# Keyed by ``str`` so lookups with an arbitrary (possibly unregistered) id are
# well-typed; only the four registered ``TargetExtractorId`` values are present.
_EXTRACTORS: dict[str, _Extractor] = {
    "network_target_v1": _extract_network,
    "host_target_v1": _extract_host,
    "session_target_v1": _extract_session,
    "artifact_target_v1": _extract_artifact,
}


class TrustedTargetExtractorRegistry:
    """Resolves target extractors by id from a fixed in-code table."""

    def __init__(self, extractors: dict[str, _Extractor] | None = None) -> None:
        self._extractors = dict(_EXTRACTORS if extractors is None else extractors)

    def is_registered(self, extractor_id: str) -> bool:
        return extractor_id in self._extractors

    def extract(self, extractor_id: str, data: TargetExtractionInput) -> tuple[NormalizedTarget, ...]:
        extractor = self._extractors.get(extractor_id)
        if extractor is None:
            raise TargetExtractorResolutionError(f"unregistered target extractor id: {extractor_id!r}")
        return extractor(data)


DEFAULT_TARGET_EXTRACTOR_REGISTRY = TrustedTargetExtractorRegistry()
