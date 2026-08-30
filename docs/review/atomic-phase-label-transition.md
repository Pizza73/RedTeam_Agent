# Atomic Phase Label Transition

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

Immediately before an automatic Phase transition, the Gate now re-fetches the
PR and requires the exact open state, reviewed HEAD, and current single Phase.
It derives one complete final label set that:

- preserves `ai-loop` and unrelated labels;
- removes every old Phase and managed transient state label; and
- adds exactly the next Phase plus `ai-needs-implementation`.

The Gate writes that full set with one `issues.setLabels` call. It then
re-fetches the PR and requires the open state, reviewed HEAD, exactly one next
Phase, and byte-for-byte-equivalent sorted label set. Drift fails closed.

## Regression evidence

- Static workflow validation requires the atomic set call and both pre/post
  transition checks.
- Static validation forbids reintroducing separate current-Phase removal and
  next-Phase addition calls.
- Existing base-refresh workflow tests continue to prohibit label mutation in
  GitHub Actions; this change is limited to the already label-authorized Phase
  Gate workflow.

## Validation results

- focused automation and loop tests: PASS, 96 tests.
- full test suite: PASS, 248 tests.
- branch coverage: PASS, 84% total.
- focused Ruff, automation validation, compileall, and dependency consistency:
  PASS.
- exact `bash scripts/ci/run_phase_gate.sh phase-0a`: automation validation
  passed, then stopped on the 88 unchanged Phase 0A application Ruff findings
  already corrected on PR #3.

## Safety constraints

- Workflow permissions are unchanged.
- Final merge authority is unchanged.
- No branch write is added.
- No OpenAI API, secret, C2, MCP, or external-target operation is introduced.
