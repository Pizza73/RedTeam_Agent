"""The one machine-readable logical-component -> physical-module map + import rules (SystemDesign §35).

There is exactly one such map in the repository. The architecture test uses it to reject
a duplicated responsibility owner (Context / Approval / Ingestion / Planner information),
a forbidden-direction import, and an out-of-owner state-transition / digest definition.
"""

from __future__ import annotations

import ast
from pathlib import Path

# Logical component -> single physical package. The mapping is 1:1 (no logical
# responsibility is owned by two packages, and no package owns two of the sensitive
# Context/Approval/Ingestion/Planner responsibilities).
LOGICAL_TO_PHYSICAL: dict[str, str] = {
    "canonical_digest": "redteam_agent.canonical",
    "crypto_envelope": "redteam_agent.crypto",
    "audit_generation": "redteam_agent.audit",
    "typed_leases": "redteam_agent.leases",
    "encrypted_quarantine": "redteam_agent.quarantine",
    "secret_lifecycle": "redteam_agent.secrets",
    "secure_ingestion": "redteam_agent.ingestion",
    "verified_erasure": "redteam_agent.erasure",
    "retention_scheduler": "redteam_agent.retention",
    "composition": "redteam_agent.composition",
    "storage_unit_of_work": "redteam_agent.storage",
    "executor_execution": "redteam_agent.execution",
    "policy": "redteam_agent.policy",
    "approval": "redteam_agent.approval",
    "mission": "redteam_agent.mission",
    "context_authorization": "redteam_agent.context",
    "planner_information": "redteam_agent.planner_information",
}

# Forbidden import edges (importer prefix -> imported prefix). ``canonical`` and
# ``crypto`` are low-level and must not depend on domain services; ingestion must not
# reach the eraser service or the executor; the eraser must not reach ingestion.
FORBIDDEN_IMPORTS: tuple[tuple[str, str], ...] = (
    ("redteam_agent.canonical", "redteam_agent.policy"),
    ("redteam_agent.canonical", "redteam_agent.mission"),
    ("redteam_agent.canonical", "redteam_agent.ingestion"),
    ("redteam_agent.canonical", "redteam_agent.secrets"),
    ("redteam_agent.canonical", "redteam_agent.quarantine"),
    ("redteam_agent.canonical", "redteam_agent.audit"),
    ("redteam_agent.canonical", "redteam_agent.storage"),
    ("redteam_agent.crypto", "redteam_agent.ingestion"),
    ("redteam_agent.crypto", "redteam_agent.secrets"),
    ("redteam_agent.crypto", "redteam_agent.quarantine"),
    ("redteam_agent.crypto", "redteam_agent.audit"),
    ("redteam_agent.crypto", "redteam_agent.storage"),
    ("redteam_agent.crypto", "redteam_agent.execution"),
    ("redteam_agent.ingestion.service", "redteam_agent.erasure.service"),
    ("redteam_agent.ingestion", "redteam_agent.execution.executor"),
    ("redteam_agent.erasure.service", "redteam_agent.ingestion.service"),
    ("redteam_agent.leases", "redteam_agent.ingestion"),
    ("redteam_agent.leases", "redteam_agent.secrets"),
    ("redteam_agent.leases", "redteam_agent.erasure"),
)


def _module_name(src_root: Path, path: Path) -> str:
    relative = path.relative_to(src_root).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            found.add(node.module)
    return found


def find_import_violations(src_root: Path) -> list[str]:
    violations: list[str] = []
    for path in sorted(src_root.rglob("*.py")):
        module = _module_name(src_root, path)
        for imported in _imports(path):
            for importer_prefix, forbidden_prefix in FORBIDDEN_IMPORTS:
                if _matches(module, importer_prefix) and _matches(imported, forbidden_prefix):
                    violations.append(
                        f"{module} imports {imported} "
                        f"(forbidden {importer_prefix} -> {forbidden_prefix})"
                    )
    return violations


def _matches(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(prefix + ".")


def find_owner_conflicts() -> list[str]:
    """Reject a record family owned by two aggregates, or a non-1:1 physical map."""
    from redteam_agent.storage.unit_of_work import AGGREGATE_CATALOG

    conflicts: list[str] = []
    owner_of: dict[str, str] = {}
    for name, definition in AGGREGATE_CATALOG.items():
        for family in definition.record_families:
            if family in owner_of and owner_of[family] != name:
                conflicts.append(f"record family {family} owned by both {owner_of[family]} and {name}")
            owner_of[family] = name
    physical_seen: dict[str, str] = {}
    for logical, physical in LOGICAL_TO_PHYSICAL.items():
        if physical in physical_seen:
            conflicts.append(f"physical module {physical} owns two logical components: "
                             f"{physical_seen[physical]} and {logical}")
        physical_seen[physical] = logical
    return conflicts
