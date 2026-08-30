# Marked Phase Label Transition

## Current phase and input evidence

- Current implementation phase after the completed Gate: Phase 0B.
- Input reviewed SHA: `d4f25715ec3d936a383d99b107902f1b24dd5d1a`.
- Phase 0A Gate run: `33316605764`, PASS.
- Observed runner result during that run:
  `AI_LOOP=BLOCKED: pull request must have exactly one phase label, got []`.

The workflow subsequently completed with the correct final labels
`ai-loop`, `ai-needs-implementation`, and `phase-0b`; no Gate record or
implementation request was lost.

## Finding addressed

The Gate moved an automatic Phase forward with separate calls:

1. remove the current Phase label;
2. remove the transient review-passed label; and
3. add the next Phase and implementation labels.

The local runner polled between steps 1 and 3, observed zero Phase labels, and
correctly stopped. Although restarting the runner recovered from the final
GitHub state, the race prevented unattended operation and could recur after
every Phase PASS.

## Fix

The final protocol uses the existing `ai-review-passed` label as a transition
marker. While it is present, the Runner accepts only one Phase or exactly two
adjacent Phases and waits without implementation or review side effects. The
Gate performs the following targeted operations:

1. revalidate the open PR, reviewed HEAD, current Phase, and marker;
2. add the next Phase and validate the marked adjacent pair;
3. remove the current Phase and validate the marked next Phase;
4. add `ai-needs-implementation` and create the exact-HEAD status/request; and
5. revalidate once more, remove only the marker, and validate the mutation
   response before completing.

No operation replaces the complete label set, so an unrelated concurrent label
cannot be erased by a stale snapshot. Conflicting/non-adjacent Phase labels,
marker removal, HEAD drift, and closed PR state fail closed at the next boundary.
The protocol itself never creates a zero-Phase state because it adds next before
removing current.

Codex found two P1 variants in the earlier full-replacement design: a writer
between snapshot and replacement could be overwritten, and any finite final
event audit left another tail window. GitHub documents no conditional unsafe
request for this label endpoint. Removing stale full replacement eliminates the
write-loss root cause instead of adding another inherently non-atomic read.

## Regression evidence

- The checked-in Python production helper is executed against an in-memory GitHub
  API double, rather than tested only through source-string assertions.
- Positive coverage verifies unrelated-label preservation, next-before-current
  ordering, a marked adjacent-Phase window, exact final state, and marker-last
  release.
- Negative/failure coverage injects a conflicting Phase, early marker removal,
  a same-label concurrent add, and a conflicting Phase at marker release.
- Python tests verify that the Runner accepts only marked adjacent transitions
  and still rejects unmarked, non-adjacent, zero, and 3-Phase ambiguity.
- Static validation forbids `issues.setLabels` in the Gate and helper.

## Resulting change set

- `.github/workflows/ai-loop-control.yml`: emit a validated transition payload
  and run the checked-out helper at the workflow SHA.
- `automation/transition_phase.py`: strict payload/marker validation, targeted
  GitHub API client, and the production transition protocol.
- `automation/run_phase_loop.py`: wait on marked single/adjacent-dual Phase
  states while retaining fail-closed handling for every other ambiguity.
- `tests/unit/test_phase_transition.py`: executable positive, negative,
  concurrent-write, release-response, and malformed-input tests.
- `tests/unit/test_phase_loop.py` and
  `tests/unit/test_automation_validation.py`: Runner and governance regressions.
- Requirements, acceptance criteria, threat model, development-loop guide, and
  this report now describe the final marked protocol.
- Existing base-refresh workflow tests continue to prohibit label mutation in
  GitHub Actions; this change is limited to the already label-authorized Phase
  Gate workflow.

## Validation results

- focused automation, loop, and transition tests: PASS, 127 tests.
- full test suite: PASS, 279 tests.
- branch coverage: PASS, 84% total.
- focused Ruff, automation validation, compileall, and dependency consistency:
  PASS.
- exact `bash scripts/ci/run_phase_gate.sh phase-0a`: automation validation
  passed, then stopped on the 88 unchanged Phase 0A application Ruff findings
  already corrected on PR #3.

## Remaining findings and constraints

- GitHub's label endpoint has no documented compare-and-swap support for unsafe
  updates; this protocol therefore forbids stale full-label replacement.
- The governance branch does not duplicate PR #3's 88 application-only Ruff
  fixes. CI and the focused/full suites above validate the governance change;
  the exact local Gate records that known branch separation without weakening
  or skipping a check.
- A failed or unknown-outcome GitHub mutation is not retried automatically. The
  transition marker remains a fail-closed recovery boundary.

## Safety constraints

- Workflow permissions are unchanged.
- Final merge authority is unchanged.
- No branch write is added.
- No OpenAI API, secret, C2, MCP, or external-target operation is introduced.
