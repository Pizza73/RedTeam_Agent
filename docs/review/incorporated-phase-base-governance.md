# Incorporated Phase Base Governance Report

## Decision and incident

PR #3 was refreshed to main SHA `79c31c966b81267b32045c4726db9ab716f49af8`, producing implementation
HEAD `7262290260c0455bff8d7b38c8ac7cfcedeb87b6`. Phase 0A CI and the exact-HEAD Codex review passed.
The separate stale-review governance fix then advanced main to
`2fe91db9757f9b5a7012c5487083122e925346db` before the Phase Gate was recorded. The runner rejected
the existing trusted refresh as stale and could neither record the completed review nor obtain the
current-HEAD PASS needed to authorize another refresh.

The safe review base is not a later default-branch SHA that the reviewed HEAD does not contain. It is
the trusted refresh target that is proven to be an ancestor of that HEAD. The runner now returns that
incorporated target for Phase 0A review even if main subsequently advances.

## Safety boundary

- Both the old pre-refresh HEAD and the recorded target base must be ancestors of the reviewed HEAD.
- The independent review, trigger, PASS and Gate remain bound to the complete current PR HEAD and the
  incorporated target SHA.
- After the Gate advances the label to the adjacent next Phase, existing LOOP-020 logic compares the
  same HEAD with current main, records a new exact-SHA refresh authorization, rolls back to Phase 0A,
  and requires a new Gate on the next refreshed HEAD.
- The earlier PASS cannot authorize next-Phase implementation across the newer default branch.
- No workflow, label, branch-update, merge permission or OpenAI API usage changes.

## Regression and validation

- The Phase 0A base test now proves that a later default branch does not replace the trusted target
  already incorporated in the review HEAD.
- Existing negative coverage still rejects a refreshed HEAD that lacks either authorized ancestry.
- Focused Ruff: PASS.
- Focused unit tests: PASS, 94 tests.
- Full tests: PASS, 246 tests; no skip or xfail was added.
- Branch coverage: PASS, 75% total.
- Automation validator, compileall, workflow YAML parsing and dependency check: PASS.
- Exact `bash scripts/ci/run_phase_gate.sh phase-0a`: FAIL at the unchanged 88 repository-wide
  Phase 0A Ruff findings on the governance base.

The correction does not suppress those application findings. PR #3 contains their fixes and must
pass the complete Gate after the next bounded refresh.

## Implementation report

- Current phase: Phase 0A revalidation on PR #3.
- Input review SHA: `7262290260c0455bff8d7b38c8ac7cfcedeb87b6`.
- Modified files: `automation/run_phase_loop.py`, `tests/unit/test_phase_loop.py`,
  `docs/acceptance-criteria.md`, `docs/ai-development-loop.md`, `docs/threat-model.md`, and this
  report.
- Finding addressed: current main incorrectly replaced the exact incorporated review base.
- Remaining constraint: after this governance merge, PR #3 intentionally requires another bounded
  refresh and fresh Phase 0A Gate before Phase 0B implementation.
