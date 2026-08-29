#!/usr/bin/env python3
"""Fail closed when an AI-loop PR changes governance-controlled files."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import PurePosixPath

PROTECTED_FILES = frozenset(
    {
        "AGENTS.md",
        "SystemDesign.md",
        "docs/acceptance-criteria.md",
        "docs/ai-development-loop.md",
        "docs/ai-loop-runbook.md",
        "docs/implementation-status.md",
        "docs/requirements.md",
        "docs/safety-invariants.md",
        "docs/threat-model.md",
        "pyproject.toml",
        "requirements.lock",
        "scripts/ci/run_phase_gate.sh",
        "scripts/ci/validate_automation.py",
    }
)
PROTECTED_PREFIXES = (".github/", "automation/", "prompts/phases/")


class GovernanceInputError(ValueError):
    """Raised when changed-path or label input is malformed."""


@dataclass(frozen=True)
class GovernanceResult:
    allowed: bool
    protected_paths: tuple[str, ...]
    reason: str


def _normalize_repo_path(raw_path: str) -> str:
    if not raw_path or "\x00" in raw_path or "\\" in raw_path:
        raise GovernanceInputError("changed path is empty or malformed")
    path = PurePosixPath(raw_path)
    if path.is_absolute() or ".." in path.parts or str(path) != raw_path:
        raise GovernanceInputError(f"changed path is not canonical: {raw_path!r}")
    return raw_path


def is_protected_path(raw_path: str) -> bool:
    path = _normalize_repo_path(raw_path)
    return path in PROTECTED_FILES or path.startswith(PROTECTED_PREFIXES)


def evaluate_governance(changed_paths: list[str], labels: set[str]) -> GovernanceResult:
    normalized = [_normalize_repo_path(path) for path in changed_paths]
    protected = tuple(sorted(path for path in normalized if is_protected_path(path)))
    if not protected:
        return GovernanceResult(True, (), "no governance-controlled files changed")
    if "ai-loop" in labels:
        return GovernanceResult(
            False,
            protected,
            "AI-loop pull requests cannot change governance-controlled files",
        )
    if "governance-change" not in labels:
        return GovernanceResult(
            False,
            protected,
            "governance changes require the governance-change label and human review",
        )
    return GovernanceResult(
        True,
        protected,
        "explicit governance-change pull request; CODEOWNERS review is still required",
    )


def _parse_labels(raw_labels: str) -> set[str]:
    try:
        value = json.loads(raw_labels)
    except json.JSONDecodeError as exc:
        raise GovernanceInputError("labels must be a JSON array") from exc
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise GovernanceInputError("labels must be a JSON array of strings")
    return set(value)


def _read_nul_paths() -> list[str]:
    raw = sys.stdin.buffer.read()
    if not raw:
        return []
    if not raw.endswith(b"\x00"):
        raise GovernanceInputError("changed paths must be NUL terminated")
    try:
        return [item.decode("utf-8") for item in raw[:-1].split(b"\x00")]
    except UnicodeDecodeError as exc:
        raise GovernanceInputError("changed paths must be UTF-8") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--labels-json", required=True)
    args = parser.parse_args()
    try:
        result = evaluate_governance(_read_nul_paths(), _parse_labels(args.labels_json))
    except GovernanceInputError as exc:
        print(f"GOVERNANCE_CHECK=BLOCKED: {exc}", file=sys.stderr)
        return 2

    print(f"GOVERNANCE_CHECK={'PASS' if result.allowed else 'BLOCKED'}: {result.reason}")
    for path in result.protected_paths:
        print(f"protected: {path}")
    return 0 if result.allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
