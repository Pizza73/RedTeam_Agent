"""Architecture ownership / import checks (SystemDesign §35)."""

from __future__ import annotations

from pathlib import Path

from redteam_agent.architecture import (
    LOGICAL_TO_PHYSICAL,
    find_import_violations,
    find_owner_conflicts,
)

_SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "redteam_agent"


def test_no_forbidden_direction_imports() -> None:
    violations = find_import_violations(_SRC_ROOT)
    assert violations == [], f"forbidden imports: {violations}"


def test_no_duplicate_responsibility_owner() -> None:
    conflicts = find_owner_conflicts()
    assert conflicts == [], f"owner conflicts: {conflicts}"


def test_logical_to_physical_is_one_to_one() -> None:
    physical = list(LOGICAL_TO_PHYSICAL.values())
    assert len(physical) == len(set(physical))


def test_sensitive_owners_are_distinct_packages() -> None:
    # Context / Approval / Ingestion / Planner-information owners must be distinct.
    sensitive = {
        LOGICAL_TO_PHYSICAL["context_authorization"], LOGICAL_TO_PHYSICAL["approval"],
        LOGICAL_TO_PHYSICAL["secure_ingestion"], LOGICAL_TO_PHYSICAL["planner_information"],
    }
    assert len(sensitive) == 4
