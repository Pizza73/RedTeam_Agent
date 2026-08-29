from pathlib import Path

REPORT_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "review" / "phase-0a-fix-report.md"
)
INPUT_REVIEW_SHA = "fb3e2e8947e0402fa55ca1520ee71f9ad24367e3"
PHASE_BASE_SHA = "2e50db4dbcc127d87237c212b909edb499c1bd34"
REVIEWED_BRANCH = "ai/redteam-agent-phase-loop"


def test_phase_0a_report_is_bound_to_the_reviewed_revision() -> None:
    report = REPORT_PATH.read_text(encoding="utf-8")

    assert f"| Input independent review SHA | `{INPUT_REVIEW_SHA}` |" in report
    assert f"| Phase base SHA | `{PHASE_BASE_SHA}` |" in report
    assert f"| Reviewed branch | `{REVIEWED_BRANCH}` |" in report


def test_phase_0a_report_rejects_superseded_worktree_evidence() -> None:
    report = REPORT_PATH.read_text(encoding="utf-8")

    assert "21be5c06e70b7e8bc5c8184af363d1cf88d61802" not in report
    assert "DIRTY（意図的、未commit）" not in report
    assert "| Branch | `main` |" not in report
