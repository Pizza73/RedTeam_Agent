# Stale Native Review Filter Governance Report

## Decision and incident

After PR #12 was merged, the local Phase loop successfully rolled PR #3 back to Phase 0A, refreshed
the branch, and obtained passing CI on new HEAD
`7262290260c0455bff8d7b38c8ac7cfcedeb87b6`. It posted a trusted current-HEAD Codex review trigger,
then stopped with `Codex PASS comment refers to a stale commit` before that review completed.

The long-lived PR contains valid Codex PASS history for older HEADs. The parser checked each
historical comment's commit prefix before checking whether the comment predated the current trusted
trigger. Historical evidence therefore blocked a fresh review even though it had no authority in
the current trigger window.

## Fail-closed correction

The parser now reads the trusted reviewer comment timestamp first and ignores comments at or before
the current exact-SHA trigger. For comments after the trigger, all existing fail-closed checks remain:

- exactly one reviewed-commit field;
- a matching current-HEAD prefix of at least ten characters;
- trusted reviewer identity and permalink;
- reviewer-authored thumbs-up after the PASS comment; and
- no PR head synchronization before completion.

Post-trigger stale or ambiguous evidence still raises a typed `UntrustedEvidenceError`. No reviewer,
workflow, label, branch-update or merge permission changes are introduced. No OpenAI API or metered
API service is used.

## Regression and validation

- A new regression supplies an older no-major-issues comment for another SHA before the trusted
  trigger and a valid current-HEAD PASS after it; only the current PASS is accepted.
- The existing regression still rejects the same stale commit evidence when it appears after the
  trusted trigger.
- Focused Ruff: PASS.
- Focused unit tests: PASS, 94 tests.
- Full tests: PASS, 246 tests; no skip or xfail was added.
- Branch coverage: PASS, 75% total.
- Automation validator, Python compileall and all workflow YAML parsing: PASS.
- Dependency check: PASS, no broken requirements.
- Exact `bash scripts/ci/run_phase_gate.sh phase-0a`: FAIL at the unchanged 88 repository-wide
  Phase 0A Ruff findings on the governance base.

The correction does not change or suppress those application findings. They are already fixed on
the long-lived implementation PR and must be revalidated after the next bounded base refresh.

## Implementation report

- Current phase: Phase 0A revalidation on PR #3.
- Input review SHA: `7262290260c0455bff8d7b38c8ac7cfcedeb87b6`.
- Finding addressed: historical stale PASS evidence incorrectly blocked a new exact-HEAD review.
- Modified files: `automation/run_phase_loop.py`, `tests/unit/test_phase_loop.py`,
  `docs/acceptance-criteria.md`, and this report.
- Resulting diff: reorder the trusted-trigger time boundary before commit-prefix validation and add
  one positive historical-evidence regression while preserving the existing post-trigger negative
  regression.
- Remaining constraint: PR #3 must be refreshed again after this governance merge and Phase 0A must
  receive a new exact-HEAD review; no old PASS is reused.
