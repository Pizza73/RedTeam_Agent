# Phase Gate Commit Status Response Fix

## Scope

This governance-only fix addresses the failed Phase 0A review-record run
`33314705383`. It does not change a project Phase implementation, phase order,
workflow permissions, merge authority, or external execution behavior.

## Root cause

The Gate obtains base-refresh statuses with
`listCommitStatusesForRef(ref: pass.reviewed_sha)`. GitHub's status response does
not include a `sha` property. The workflow nevertheless compared `status.sha`
with the Phase 0A PASS SHA, so a valid status obtained from the exact trusted ref
was always rejected.

The failed run provided a valid status with all of the remaining bindings:

- creator: `github-actions[bot]`
- state: `success`
- exact transition context, including the target base SHA
- fixed trusted description
- target URL equal to the prior Phase 0A PASS permalink

## Fix and retained bindings

The nonexistent `status.sha` comparison is removed. The commit binding remains
at the API boundary because statuses are fetched from
`ref: pass.reviewed_sha`. The Gate continues to require:

- a trusted, SHA-bound prior Phase 0A PASS record;
- the exact `phase-0b` to `phase-0a` transition context;
- a lowercase 40-character target base SHA in that context;
- `github-actions[bot]` provenance, success state, and the fixed description;
- the status target URL bound to the exact prior PASS comment;
- old-head and target-base ancestry of the reviewed head;
- exact live PR head and phase revalidation before recording the Gate.

## Regression evidence

`test_phase_gate_uses_fail_closed_native_codex_evidence_chain` now requires the
exact-ref API binding and rejects reintroduction of the nonexistent response
field comparison.

## Validation results

- `.venv/bin/python -m pytest -q tests/unit/test_automation_validation.py`:
  PASS, 10 tests.
- `.venv/bin/ruff check tests/unit/test_automation_validation.py`: PASS.
- `.venv/bin/python scripts/ci/validate_automation.py`:
  `AUTOMATION_VALIDATION=PASS`.
- `.venv/bin/python -m pytest -q tests --strict-markers`: PASS, 246 tests.
- branch coverage: PASS, 84% total.
- `.venv/bin/python -m compileall -q src/redteam_agent`: PASS.
- `.venv/bin/python -m pip check`: PASS.
- `bash scripts/ci/run_phase_gate.sh phase-0a`: stopped after automation
  validation on 88 Ruff findings in unchanged Phase 0A application files.
- `.venv/bin/python -m mypy src/redteam_agent`: 40 findings in unchanged
  Phase 0A application files.

The application lint and type findings are addressed on the long-lived Phase
implementation PR and are not modified by this governance-only repair.

## Constraints

The prior failed workflow made no PR label, status-success, or branch changes.
The Phase loop must be restarted only after this change passes CI, receives an
independent exact-HEAD review, and is merged without an administrative bypass.
