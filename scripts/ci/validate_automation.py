#!/usr/bin/env python3
"""Validate AI-loop JSON with duplicate-aware parsing and closed schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

EXPECTED_PHASES = (
    "phase-0a",
    "phase-0b",
    "phase-0c",
    "phase-1",
    "phase-2",
    "phase-3",
    "phase-4",
    "phase-5",
)


class AutomationValidationError(ValueError):
    """Raised when AI-loop control data is malformed or inconsistent."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AutomationValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_load(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AutomationValidationError(f"invalid JSON file: {path}") from exc


def _validate_instance(instance_path: Path, schema_path: Path) -> Any:
    schema = strict_json_load(schema_path)
    instance = strict_json_load(instance_path)
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(instance)
    except Exception as exc:
        raise AutomationValidationError(
            f"schema validation failed: {instance_path} against {schema_path}"
        ) from exc
    return instance


def validate_automation(repo_root: Path) -> None:
    root = repo_root.resolve(strict=True)
    schemas = root / "automation" / "schemas"
    for schema_name in (
        "implementation-request.schema.json",
        "invariant-audit.schema.json",
        "invariant-families.schema.json",
        "review-result.schema.json",
        "phase-plan.schema.json",
        "provider-gates.schema.json",
        "final-merge-policy.schema.json",
    ):
        schema = strict_json_load(schemas / schema_name)
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            raise AutomationValidationError(f"invalid JSON schema: {schema_name}") from exc

    plan = _validate_instance(
        root / "automation" / "phase-plan.json",
        schemas / "phase-plan.schema.json",
    )
    phase_ids = tuple(item["id"] for item in plan["phases"])
    if phase_ids != EXPECTED_PHASES:
        raise AutomationValidationError(f"unexpected phase order: {phase_ids}")
    for index, item in enumerate(plan["phases"]):
        if item["label"] != item["id"]:
            raise AutomationValidationError(f"phase label mismatch: {item['id']}")
        expected_auto_start = index < 6
        if item["auto_start"] is not expected_auto_start:
            raise AutomationValidationError(f"unexpected auto_start for {item['id']}")
        prompt_path = (root / item["prompt"]).resolve(strict=True)
        if not prompt_path.is_relative_to(root / "prompts" / "phases") or not prompt_path.is_file():
            raise AutomationValidationError(f"invalid phase prompt path: {item['prompt']}")

    invariant_policy = _validate_instance(
        root / "automation" / "invariant-families.json",
        schemas / "invariant-families.schema.json",
    )
    family_ids = [item["id"] for item in invariant_policy["families"]]
    if len(set(family_ids)) != len(family_ids):
        raise AutomationValidationError("duplicate invariant-family ID")
    known_families = set(family_ids)
    if tuple(invariant_policy["phases"]) != EXPECTED_PHASES:
        raise AutomationValidationError("invariant-family phase mapping is incomplete or unordered")
    for phase, families in invariant_policy["phases"].items():
        if not set(families).issubset(known_families):
            raise AutomationValidationError(f"unknown invariant family for {phase}")

    gates = _validate_instance(
        root / "automation" / "provider-gates.json",
        schemas / "provider-gates.schema.json",
    )
    for phase in ("phase-4", "phase-5"):
        gate = gates[phase]
        values = [value for key, value in gate.items() if key != "approved"]
        if gate["approved"] is True and any(
            not isinstance(value, str) or not value.strip() for value in values
        ):
            raise AutomationValidationError(f"approved provider gate is incomplete: {phase}")

    merge_policy = _validate_instance(
        root / "automation" / "final-merge-policy.json",
        schemas / "final-merge-policy.schema.json",
    )
    if tuple(merge_policy["required_checks"]) != (
        "tests (3.12)",
        "tests (3.14)",
        "quality",
        "governance-integrity",
    ):
        raise AutomationValidationError("unexpected automatic final-merge check set")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        validate_automation(args.repo_root)
    except AutomationValidationError as exc:
        print(f"AUTOMATION_VALIDATION=BLOCKED: {exc}")
        return 1
    print("AUTOMATION_VALIDATION=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
