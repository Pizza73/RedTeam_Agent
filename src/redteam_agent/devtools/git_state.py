"""Read-only git state inspection (H-07).

Provides the current commit, branch and working-tree status so a development
record can cite the exact implementation state. This never mutates the
repository and never runs a shell; arguments are a fixed argv list.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GitState:
    commit: str
    branch: str
    is_clean: bool
    status_lines: tuple[str, ...]


class GitStateError(RuntimeError):
    """Raised when git state cannot be read."""


def _run_git(repo_root: Path, args: list[str]) -> str:
    command = ["git", *args]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, git from PATH, no shell
            command,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as exc:  # pragma: no cover - git always present here
        raise GitStateError("git executable not found") from exc
    except subprocess.CalledProcessError as exc:
        raise GitStateError(f"git {' '.join(args)} failed with code {exc.returncode}") from exc
    return completed.stdout.strip()


def read_git_state(repo_root: str | Path) -> GitState:
    root = Path(repo_root)
    commit = _run_git(root, ["rev-parse", "HEAD"])
    branch = _run_git(root, ["rev-parse", "--abbrev-ref", "HEAD"])
    status = _run_git(root, ["status", "--porcelain"])
    status_lines = tuple(line for line in status.splitlines() if line)
    return GitState(commit=commit, branch=branch, is_clean=not status_lines, status_lines=status_lines)
