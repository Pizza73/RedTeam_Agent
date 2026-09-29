"""Git state inspection (H-07)."""

from __future__ import annotations

from pathlib import Path

from redteam_agent.devtools.git_state import read_git_state

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_read_git_state_returns_commit_and_branch() -> None:
    state = read_git_state(_REPO_ROOT)
    assert len(state.commit) == 40
    assert all(c in "0123456789abcdef" for c in state.commit)
    assert state.branch != ""
    # is_clean reflects the presence of status lines deterministically.
    assert state.is_clean == (len(state.status_lines) == 0)
