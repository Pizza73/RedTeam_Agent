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
        or "\\" in raw
        or "\x00" in raw
        or path.is_absolute()
        or ".." in path.parts
        or str(path) != path_text
        or (test_only and not path_text.startswith("tests/"))
    ):
        raise InvariantAuditError(f"audit evidence path is not canonical: {raw!r}")
    try:
        resolved = (root / path_text).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise InvariantAuditError(f"audit evidence path is unavailable: {raw!r}") from exc
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


def _git_bytes(root: Path, *arguments: str) -> bytes:
    git = shutil.which("git")
    if git is None:
        raise InvariantAuditError("git is required for implementation strategy evidence")
    result = subprocess.run(  # noqa: S603 - fixed read-only operations, no shell.
        [git, *arguments], cwd=root, capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise InvariantAuditError("implementation strategy Git evidence is unavailable")
    return result.stdout


def _git_json(root: Path, commit: str, path: str) -> Any:
    try:
        return json.loads(
            _git_bytes(root, "show", f"{commit}:{path}"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InvariantAuditError("historical audit Git JSON is invalid") from exc


def _historical_preflight_policy(
    root: Path, audit_path: Path, audit: dict[str, Any],
) -> Any:
    """Read an unchanged legacy report, never certify new implementation evidence.

    Neither this local history check nor its digest is Resume/Review authority. The
    trusted workflows still require the exact-HEAD checkpoint, Design Approval and
    new-policy request/strategy before implementation or formal review.
    """
    relative_path = audit_path.relative_to(root).as_posix()
    record_commit = _git_bytes(
        root, "log", "-1", "--format=%H", "HEAD", "--", relative_path,
    ).decode("ascii").strip()
    if len(record_commit) != 40 or any(c not in "0123456789abcdef" for c in record_commit):
        raise InvariantAuditError("historical audit must already be committed")
    _require_ancestor(root, record_commit, require_output_commit=True)
    if _git_bytes(root, "show", f"{record_commit}:{relative_path}") != audit_path.read_bytes():
        raise InvariantAuditError("historical audit differs from its committed record")
    request_head = audit["request"]["head_sha"]
    if request_head == record_commit:
        raise InvariantAuditError("historical audit needs a proper-ancestor input request")
    _git_bytes(root, "merge-base", "--is-ancestor", request_head, record_commit)

    legacy_requirement = {"policy_version": "1.0", "required": True}
    for commit in (request_head, record_commit):
        plan = _git_json(root, commit, "automation/phase-plan.json")
        if not isinstance(plan, dict) or plan.get("invariant_audit") != legacy_requirement:
            raise InvariantAuditError("historical audit was not recorded under the legacy policy")
    policy_path = "automation/invariant-families.json"
    policy = _git_json(root, request_head, policy_path)
    if policy != _git_json(root, record_commit, policy_path):
        raise InvariantAuditError("historical audit policy changed between input and recording")

    # A carried-forward audit cannot cover new application code or changed evidence.
    if _git_bytes(root, "diff", "--no-ext-diff", "--name-only", record_commit, "--", "src"):
        raise InvariantAuditError("historical audit cannot cover changed application code")
    if _git_bytes(root, "ls-files", "--others", "--exclude-standard", "--", "src"):
        raise InvariantAuditError("historical audit cannot cover untracked application code")
    evidence = set(audit["cross_family_tests"])
    for family in audit["families"]:
        for field in ("entry_points", "sibling_paths", "tests"):
            evidence.update(family[field])
    for raw in evidence:
        path = _repo_path(root, raw)
        recorded = _git_bytes(root, "show", f"{record_commit}:{raw.partition('#')[0]}")
        if path.read_bytes() != recorded:
            raise InvariantAuditError("historical audit evidence changed since recording")
    return policy


def _require_input_path(root: Path, request_head: str, raw: str) -> None:
    path = PurePosixPath(raw)
    if not raw or "#" in raw or "\\" in raw or "\x00" in raw or (
        path.is_absolute() or ".." in path.parts or str(path) != raw
    ):
        raise InvariantAuditError("implementation input path is not canonical")
    if _git_bytes(root, "cat-file", "-t", f"{request_head}:{raw}").strip() != b"blob":
        raise InvariantAuditError("implementation input path is not a file at input HEAD")


def _validate_implementation_strategy(
    root: Path,
    audit: dict[str, Any],
    family_by_id: dict[str, Any],
    required_families: list[str],
    *,
    required: bool,
) -> None:
    strategy = audit.get("implementation_strategy")
    if strategy is None:
        if required:
            raise InvariantAuditError("trusted request requires implementation strategy evidence")
        return  # Historical reports are readable, not authority for a new-policy request.
    units = strategy["units"]  # Closed schema has already validated all structural fields.
    ids = [unit["id"] for unit in units]
    if len(ids) != len(set(ids)):
        raise InvariantAuditError("implementation unit IDs must be unique")
    request_head = audit["request"]["head_sha"]
    allowed_specs = {
        "SystemDesign.md", "SystemDesign_AI_Control.md", "docs/requirements.md",
        "docs/acceptance-criteria.md", "docs/safety-invariants.md",
    }
    plan = _load_json(root / "automation" / "phase-plan.json")
    _validate(plan, _load_json(root / "automation/schemas/phase-plan.schema.json"),
              name="phase plan")
    phase_configs = [item for item in plan["phases"] if item["id"] == audit["phase"]]
    if len(phase_configs) != 1:
        raise InvariantAuditError("implementation strategy phase prompt is ambiguous or missing")
    phase_config = phase_configs[0]
    allowed_specs.add(phase_config["prompt"])
    input_paths: set[str] = set()
    output_paths: set[str] = set()
    covered_families: set[str] = set()
    for unit in units:
        families = set(unit["invariant_families"])
        if not families.issubset(required_families):
            raise InvariantAuditError("implementation unit references a non-current-phase family")
        covered_families.update(families)
        for raw in unit["input_paths"]:
            _require_input_path(root, request_head, raw)
            input_paths.add(raw)
        for raw in unit["output_paths"]:
            if "#" in raw:
                raise InvariantAuditError("output_paths must name whole repository files")
            _repo_path(root, raw)
            output_paths.add(raw)
        for field in ("entry_points", "sibling_paths"):
            for raw in unit[field]:
                _repo_path(root, raw)
        for raw in unit["specification_refs"]:
            if raw.partition("#")[0] not in allowed_specs:
                raise InvariantAuditError("implementation unit must cite current normative specs")
            _repo_path(root, raw)
        for raw in unit["tests"]:
            _repo_path(root, raw, test_only=True)
        modes = set(unit["test_modes"])
        if not {"positive", "negative", "failure"}.issubset(modes):
            raise InvariantAuditError("implementation unit lacks positive/negative/failure tests")
        if unit["disposition"] != "reuse" and any(
            family_by_id[family]["stateful"] for family in families
        ) and not modes.intersection({"property", "state-machine"}):
            raise InvariantAuditError("stateful replacement/new unit lacks model-based tests")

    affected = {item["id"] for item in audit["families"] if item["status"] == "affected"}
    if not affected.issubset(covered_families):
        raise InvariantAuditError("implementation units omit an affected invariant family")
    changed = _git_bytes(root, "diff", "--no-renames", "--name-only", "-z", request_head,
                         "--", "src", "tests")
    untracked = _git_bytes(root, "ls-files", "--others", "--exclude-standard", "-z",
                           "--", "src", "tests")
    try:
        changed_paths = {name.decode("utf-8") for name in (changed + untracked).split(b"\x00")
                         if name}
    except UnicodeError as exc:
        raise InvariantAuditError("implementation paths must be valid UTF-8") from exc
    changed_outputs = {name for name in changed_paths if (root / name).exists()}
    deleted_inputs = changed_paths - changed_outputs
    if not changed_outputs.issubset(output_paths) or not deleted_inputs.issubset(input_paths):
        raise InvariantAuditError("implementation units omit changed source/test paths")


def validate_invariant_audit(
    repo_root: Path,
    phase: str,
    *,
    if_present: bool = False,
    require_output_commit: bool = False,
    expected_request_head: str | None = None,
    expected_request_action: str | None = None,
    expected_request_reference: str | None = None,
    require_implementation_strategy: bool = False,
    historical_preflight: bool = False,
) -> str | None:
    if historical_preflight and (
        not if_present or require_output_commit or require_implementation_strategy
        or any(value is not None for value in (
            expected_request_head, expected_request_action, expected_request_reference,
        ))
    ):
        raise InvariantAuditError("historical preflight cannot certify a trusted output request")
    root = repo_root.resolve(strict=True)
    audit_path = root / "docs" / "review" / f"{phase}-invariant-audit.json"
    if not audit_path.is_file():
        if if_present and not require_implementation_strategy:
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

    if historical_preflight and "implementation_strategy" not in audit:
        historical = _historical_preflight_policy(root, audit_path, audit)
        _validate(historical, _load_json(schemas / "invariant-families.schema.json"),
                  name="historical invariant-family policy")
        if historical["phases"].get(phase) != policy["phases"].get(phase):
            raise InvariantAuditError("historical audit cannot replace the current family set")
        policy = historical

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
    _validate_implementation_strategy(
        root, audit, family_by_id, required, required=require_implementation_strategy,
    )

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
    parser.add_argument("--require-implementation-strategy", action="store_true")
    parser.add_argument("--historical-preflight", action="store_true")
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
            require_implementation_strategy=args.require_implementation_strategy,
            historical_preflight=args.historical_preflight,
        )
    except (InvariantAuditError, OSError, subprocess.SubprocessError) as exc:
        print(f"INVARIANT_AUDIT=BLOCKED: {exc}")
        return 1
    if digest is None:
        print("INVARIANT_AUDIT=NOT_REQUIRED")
    elif args.historical_preflight:
        print(f"INVARIANT_AUDIT=PREFLIGHT_ONLY:{digest}")
    else:
        print(f"INVARIANT_AUDIT=PASS:{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
