"""Deterministic approval presentation builder (SystemDesign §23, B-05).

The presentation is derived from the PolicyDecision, tool definition and the
current session context. It reproduces every authorization-relevant field
exactly (tool, all targets/bindings, session/principal, canonical argument
keys/types/presence, side effect, timeout, secret version references and
counts, data-access resources/operations). Secret values are never shown; only
references and counts. This is the single source of the presentation digest.
"""

from __future__ import annotations

from typing import Any

from redteam_agent.approval.models import (
    ApprovalDataAccessSummary,
    ApprovalPresentation,
    ApprovalSecretReferenceSummary,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import thaw
from redteam_agent.errors import SecretArgumentBindingError
from redteam_agent.policy.models import PolicyDecision
from redteam_agent.tools.models import ToolDefinition
from redteam_agent.tools.secret_argument_path import parse_json_pointer, resolve_pointer


def _redact_subtree(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact_subtree(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_subtree(item) for item in value]
    if isinstance(value, str):
        return "<redacted>"
    return value


def _set_at_pointer(root: dict[str, Any], tokens: tuple[str, ...], new_value: Any) -> None:
    cursor: Any = root
    for token in tokens[:-1]:
        cursor = cursor[token]
    cursor[tokens[-1]] = new_value


def redact_arguments(arguments: Any, secret_paths: tuple[str, ...]) -> dict[str, Any]:
    """Return a plain-dict copy with secret subtrees value-redacted.

    Argument keys, nesting and value types are preserved; only string values
    inside a secret reference subtree are replaced.
    """
    plain = thaw(arguments)
    if not isinstance(plain, dict):
        raise SecretArgumentBindingError("arguments must be a JSON object")
    for path in secret_paths:
        tokens = parse_json_pointer(path)
        leaf = resolve_pointer(tokens, plain)
        _set_at_pointer(plain, tokens, _redact_subtree(leaf))
    return plain


def _secret_summaries(
    arguments: Any, secret_paths: tuple[str, ...]
) -> tuple[ApprovalSecretReferenceSummary, ...]:
    grouped: dict[str, dict[str, list[str]]] = {}
    plain = thaw(arguments)
    for path in secret_paths:
        tokens = parse_json_pointer(path)
        leaf = resolve_pointer(tokens, plain)
        if not isinstance(leaf, dict):
            raise SecretArgumentBindingError("secret reference must be a JSON object")
        credential_type = leaf.get("credential_type")
        version_id = leaf.get("secret_version_id")
        if not isinstance(credential_type, str) or not isinstance(version_id, str):
            raise SecretArgumentBindingError("secret reference missing credential_type/secret_version_id")
        principal = leaf.get("principal_ref")
        entry = grouped.setdefault(credential_type, {"versions": [], "principals": []})
        entry["versions"].append(version_id)
        if isinstance(principal, str):
            entry["principals"].append(principal)
    summaries: list[ApprovalSecretReferenceSummary] = []
    for credential_type in sorted(grouped):
        versions = tuple(sorted(grouped[credential_type]["versions"]))
        principals = tuple(sorted(set(grouped[credential_type]["principals"])))
        summaries.append(
            ApprovalSecretReferenceSummary(
                credential_type=credential_type,
                reference_count=len(versions),
                secret_version_ids=versions,
                associated_principal_refs=principals,
            )
        )
    return tuple(summaries)


def _data_access_summaries(decision: PolicyDecision) -> tuple[ApprovalDataAccessSummary, ...]:
    grouped: dict[tuple[str, frozenset[str]], list[Any]] = {}
    for grant in decision.authorized_data_access:
        key = (grant.resource_type, frozenset(grant.operations))
        grouped.setdefault(key, []).append(grant)
    summaries: list[ApprovalDataAccessSummary] = []
    for resource_type, operations in sorted(grouped, key=lambda k: (k[0], sorted(k[1]))):
        grants = grouped[(resource_type, operations)]
        bindings = tuple(grant.resource for grant in grants)
        ids = tuple(sorted(grant.resource.resource_id for grant in grants))
        summaries.append(
            ApprovalDataAccessSummary(
                resource_type=resource_type,
                operations=frozenset(operations),  # type: ignore[arg-type]
                resource_count=len(grants),
                resource_reference_ids=ids,
                resource_bindings=bindings,
            )
        )
    return tuple(summaries)


def _presentation_digest_payload(presentation_fields: dict[str, Any]) -> dict[str, Any]:
    payload = dict(presentation_fields)
    payload.pop("presentation_digest", None)
    return payload


def build_presentation(
    *,
    decision: PolicyDecision,
    tool: ToolDefinition,
    arguments: Any,
    current_principal_ref: str | None,
    current_principal_display: str | None,
    timeout_seconds: int,
    digest_service: DigestService,
    session_id: str | None,
) -> ApprovalPresentation:
    redacted = redact_arguments(arguments, tool.secret_argument_paths)
    secret_summaries = _secret_summaries(arguments, tool.secret_argument_paths)
    data_access = _data_access_summaries(decision)

    draft = {
        "tool_ref": tool.tool_ref.model_dump(mode="python"),
        "tool_display_name": tool.display_name,
        "normalized_targets": [t.model_dump(mode="python") for t in decision.normalized_targets],
        "target_dispatch_bindings": [b.model_dump(mode="python") for b in decision.target_dispatch_bindings],
        "target_count": len(decision.normalized_targets),
        "session_id": session_id,
        "current_principal_ref": current_principal_ref,
        "current_principal_display": current_principal_display,
        "redacted_arguments": redacted,
        "secret_reference_summaries": [s.model_dump(mode="python") for s in secret_summaries],
        "authorized_data_access_summary": [d.model_dump(mode="python") for d in data_access],
        "timeout_seconds": timeout_seconds,
        "effective_risk": decision.effective_risk,
        "side_effect": tool.side_effect,
        "truncation_reason_codes": [],
    }
    digest = digest_service.compute("presentation_digest", _presentation_digest_payload(draft))
    return ApprovalPresentation(
        tool_ref=tool.tool_ref,
        tool_display_name=tool.display_name,
        normalized_targets=decision.normalized_targets,
        target_dispatch_bindings=decision.target_dispatch_bindings,
        target_count=len(decision.normalized_targets),
        session_id=session_id,
        current_principal_ref=current_principal_ref,
        current_principal_display=current_principal_display,
        redacted_arguments=redacted,
        secret_reference_summaries=secret_summaries,
        authorized_data_access_summary=data_access,
        timeout_seconds=timeout_seconds,
        effective_risk=decision.effective_risk,
        side_effect=tool.side_effect,
        truncation_reason_codes=(),
        presentation_digest=digest,
    )
