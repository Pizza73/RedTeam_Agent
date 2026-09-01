#!/usr/bin/env python3
"""Validate the implementation-side invariant-family audit before formal review."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator


class InvariantAuditError(ValueError):
    """Raised when pre-review family evidence is missing, stale, or malformed."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvariantAuditError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InvariantAuditError(f"invalid JSON file: {path}") from exc


def _validate(instance: Any, schema: Any, *, name: str) -> None:
    errors = sorted(Draft202012Validator(schema).iter_errors(instance), key=lambda e: e.json_path)
    if errors:
        first = errors[0]
        raise InvariantAuditError(f"{name} schema failure at {first.json_path}: {first.message}")


def _repo_path(root: Path, raw: str, *, test_only: bool = False) -> Path:
    path_text = raw.partition("#")[0]
    path = PurePosixPath(path_text)
    if (
        not path_text
        or path.is_absolute()
        or ".." in path.parts
        or str(path) != path_text
        or (test_only and not path_text.startswith("tests/"))
    ):
        raise InvariantAuditError(f"audit evidence path is not canonical: {raw!r}")
    resolved = (root / path_text).resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise InvariantAuditError(f"audit evidence path is outside the repository: {raw!r}")
    return resolved


def _require_ancestor(root: Path, request_head: str, *, require_output_commit: bool) -> None:
    git = shutil.which("git")
    if git is None:
        raise InvariantAuditError("git is required to bind the audit to repository ancestry")
    current_head = subprocess.run(  # noqa: S603 - fixed git operation without shell expansion.
        [git, "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    ancestor = subprocess.run(  # noqa: S603 - SHAs are closed-schema lowercase hex values.
        [git, "merge-base", "--is-ancestor", request_head, current_head],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if ancestor.returncode != 0:
        raise InvariantAuditError("audit request head is not an ancestor of the current HEAD")
    if require_output_commit and request_head == current_head:
        raise InvariantAuditError("audit is not bound to an implementation output commit")


def validate_invariant_audit(
    repo_root: Path,
    phase: str,
    *,
    if_present: bool = False,
    require_output_commit: bool = False,
    expected_request_head: str | None = None,
    expected_request_action: str | None = None,
    expected_request_reference: str | None = None,
) -> str | None:
    root = repo_root.resolve(strict=True)
    audit_path = root / "docs" / "review" / f"{phase}-invariant-audit.json"
    if not audit_path.is_file():
        if if_present:
            return None
        raise InvariantAuditError(f"missing invariant-family audit: {audit_path}")

    schemas = root / "automation" / "schemas"
    policy = _load_json(root / "automation" / "invariant-families.json")
    audit = _load_json(audit_path)
    _validate(
        policy,
        _load_json(schemas / "invariant-families.schema.json"),
        name="invariant-family policy",
    )
    _validate(
        audit,
        _load_json(schemas / "invariant-audit.schema.json"),
        name="invariant audit",
    )
    if not isinstance(policy, dict) or not isinstance(audit, dict):
        raise InvariantAuditError("invariant policy and audit must be objects")
    if audit.get("phase") != phase:
        raise InvariantAuditError("audit phase does not match the current phase")

    family_items = policy.get("families")
    phase_map = policy.get("phases")
    if not isinstance(family_items, list) or not isinstance(phase_map, dict):
        raise InvariantAuditError("invariant-family policy has invalid collections")
    family_by_id = {
        str(item.get("id")): item for item in family_items if isinstance(item, dict)
    }
    if len(family_by_id) != len(family_items):
        raise InvariantAuditError("invariant-family policy contains duplicate IDs")
    required = phase_map.get(phase)
    if not isinstance(required, list) or any(item not in family_by_id for item in required):
        raise InvariantAuditError("phase references an unknown invariant family")

    audited = audit.get("families")
    if not isinstance(audited, list):
        raise InvariantAuditError("audit families must be an array")
    audited_ids = [item.get("id") for item in audited if isinstance(item, dict)]
    if len(audited_ids) != len(audited) or len(set(audited_ids)) != len(audited_ids):
        raise InvariantAuditError("audit must contain each family exactly once")
    if set(audited_ids) != set(required):
        raise InvariantAuditError("audit does not cover the exact required family set")

    for item in audited:
        if not isinstance(item, dict):  # schema already reports this with a precise path
            raise InvariantAuditError("audit family entry must be an object")
        for entry in item["entry_points"]:
            _repo_path(root, str(entry))
        for sibling in item["sibling_paths"]:
            _repo_path(root, str(sibling))
        for test in item["tests"]:
            _repo_path(root, str(test), test_only=True)
        modes = set(item["test_modes"])
        if not {"positive", "negative", "failure"}.issubset(modes):
            raise InvariantAuditError(
                f"{item['id']} lacks positive, negative, or failure-path test evidence"
            )
        family_policy = family_by_id[str(item["id"])]
        if (
            item["status"] == "affected"
            and family_policy.get("stateful") is True
            and not modes.intersection({"property", "state-machine"})
        ):
            raise InvariantAuditError(
                f"affected stateful family {item['id']} lacks property/state-machine evidence"
            )
    for test in audit["cross_family_tests"]:
        _repo_path(root, str(test), test_only=True)

    request = audit.get("request")
    if not isinstance(request, dict):
        raise InvariantAuditError("audit request binding must be an object")
    checks = (
        ("head_sha", expected_request_head),
        ("action", expected_request_action),
        ("reference", expected_request_reference),
    )
    for field, expected in checks:
        if expected is not None and request.get(field) != expected:
            raise InvariantAuditError(f"audit request {field} does not match trusted evidence")
    _require_ancestor(root, str(request["head_sha"]), require_output_commit=require_output_commit)

    encoded = json.dumps(audit, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--phase", required=True)
    parser.add_argument("--if-present", action="store_true")
    parser.add_argument("--require-output-commit", action="store_true")
    parser.add_argument("--expected-request-head")
    parser.add_argument("--expected-request-action")
    parser.add_argument("--expected-request-reference")
    args = parser.parse_args()
    try:
        digest = validate_invariant_audit(
            args.repo_root,
            args.phase,
            if_present=args.if_present,
            require_output_commit=args.require_output_commit,
            expected_request_head=args.expected_request_head,
            expected_request_action=args.expected_request_action,
            expected_request_reference=args.expected_request_reference,
        )
    except (InvariantAuditError, OSError, subprocess.SubprocessError) as exc:
        print(f"INVARIANT_AUDIT=BLOCKED: {exc}")
        return 1
    if digest is None:
        print("INVARIANT_AUDIT=NOT_REQUIRED")
    else:
        print(f"INVARIANT_AUDIT=PASS:{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
