# Native Codex Review Governance Report

## Decision

The human operator approved both governance changes on 2026-08-30:

1. Set `AI_REVIEWER_LOGIN` to the exact observed login
   `chatgpt-codex-connector[bot]`.
2. Replace the unsupported custom reviewer marker with fail-closed validation of native Codex
   GitHub review evidence.

The repository variable was updated and read back with the exact value. No OpenAI API key or
metered OpenAI API call is used.

Official behavior reference:
[Review GitHub pull requests with Codex](https://learn.chatgpt.com/docs/third-party/github).
Codex posts a standard GitHub review for `@codex review`, limits comments to P0/P1 findings, and
uses a thumbs-up outcome when no such finding remains.

## Full-SHA evidence chain

The shortened commit ID displayed by Codex is not accepted alone. The local orchestrator and the
approver-restricted workflow independently require all of the following:

- Current PR head is the supplied lowercase 40-character SHA.
- A `github-actions[bot]` ready marker exactly names the phase and full head SHA.
- The configured operator posts an exact `@codex review` trigger after that ready marker.
- The trigger visibly contains the full head and phase-base SHAs.
- The trigger marker digest binds ready permalink, phase, full head and phase base.
- Reviewer evidence is authored by the exact `AI_REVIEWER_LOGIN`.
- No `synchronize` event occurs between trigger and review completion.
- The four deterministic required checks are successful for the same full head SHA.

For PASS, the evidence must additionally be the standard no-major-issues comment, contain exactly
one matching commit prefix of at least 10 hexadecimal characters, have a reviewer-authored `+1`
reaction after the comment, and have no current-head P0/P1 or formal finding review. A formal review
whose inline findings were removed is rejected.

For CHANGES_REQUESTED, the evidence must be a formal Codex review whose `commit_id` equals the full
current head and whose retained inline comments contain exactly one P0/P1 badge each. The stable
root-cause key is derived from priority, path and normalized headline.

## Live evidence validation

The new orchestrator posted a fully bound review trigger against implementation PR #3:

- Ready marker: https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5465580444
- Review trigger: https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5465700133
- Native Codex result: https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5465711683
- Reviewed full head: `8ab811eaba39848fd2804c6e9ed815235362ac4c`
- Phase base: `2e50db4dbcc127d87237c212b909edb499c1bd34`
- Derived result: `PASS`, zero P0/P1 findings

The local native-evidence validator accepted that complete chain. It did not dispatch the phase
record because this governance workflow is not yet merged to the trusted default branch.

## Validation results

```text
.venv/bin/python -m pytest -q \
  tests/unit/test_phase_loop.py \
  tests/unit/test_automation_validation.py \
  tests/unit/test_governance_check.py
47 passed

.venv/bin/python -m pytest -q
182 passed

.venv/bin/python -m compileall -q automation scripts/ci
PASS

.venv/bin/python scripts/ci/validate_automation.py
AUTOMATION_VALIDATION=PASS

.venv/bin/python -m ruff check \
  automation scripts/ci \
  tests/unit/test_automation_validation.py \
  tests/unit/test_governance_check.py \
  tests/unit/test_phase_loop.py
PASS

.venv/bin/python -m mypy --ignore-missing-imports \
  automation/run_phase_loop.py \
  tests/unit/test_phase_loop.py \
  tests/unit/test_automation_validation.py
Success: no issues found in 3 source files

GitHub workflow embedded JavaScript syntax check
PASS

bash scripts/ci/run_phase_gate.sh phase-0a
FAIL at repository-wide Ruff on the default-branch Phase 0A implementation baseline
```

The full Phase 0A gate failure is pre-existing on `main`: the corrected Phase 0A application tree
is intentionally isolated in PR #3. This governance PR does not copy application changes into a
protected control branch or weaken the phase gate. Governance-mode GitHub CI runs the dedicated
automation/governance checks.

## Remaining control

This governance change must be manually reviewed and merged. After merge, start the loop from a
clean, current `main` checkout. The loop will revalidate the same PR head, request a fresh native
review if necessary, dispatch the trusted Phase 0A record, and only then create the Phase 0B
implementation request. Neither Actions nor Codex may merge either pull request.
