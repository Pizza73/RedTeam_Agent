from __future__ import annotations

import ast
from pathlib import Path


def test_phase_0a_has_no_external_dispatch_dependency() -> None:
    forbidden_roots = {
        "subprocess",
        "socket",
        "httpx",
        "requests",
        "paramiko",
        "asyncssh",
        "fabric",
    }
    imported: set[str] = set()
    for path in Path("src/redteam_agent").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
    assert imported.isdisjoint(forbidden_roots)


def test_sql_is_confined_to_storage_and_repository_layers() -> None:
    sql_tokens = ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "CREATE TABLE")
    violations: list[str] = []
    for path in Path("src/redteam_agent").rglob("*.py"):
        content = path.read_text(encoding="utf-8")
        if any(token in content for token in sql_tokens):
            relative = path.relative_to("src/redteam_agent")
            if relative.parts[0] not in {"repositories", "storage"}:
                violations.append(str(relative))
    assert violations == []
