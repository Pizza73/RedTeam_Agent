# Exhaustive Codex Review Governance Change

## Scope

This governance change strengthens the single semantic review request so Codex must complete all
review categories in one pass on one exact pull-request HEAD. The rule applies identically to every
Phase. Phase implementation is paused while this change is reviewed and merged.

## Controls added

- One SHA/base/ready-bound `@codex review` covers authorization/lifecycle, secrets and untrusted
  output, integrity/cryptography/storage/recovery/concurrency, all acceptance criteria, bypasses,
  tests, and earlier-Phase regressions.
- Codex is instructed to continue after the first issue and retain every consequential finding in
  the same native review using standard P0/P1 inline output.
- The local orchestrator and approver-restricted workflow aggregate all retained P0/P1 comments.
- The resulting fix request records the complete native review, exact `finding_count`, and every
  finding permalink. Its first `finding_key` is only a retry key; implementation must fix every
  listed finding and add security regression tests.
- The Phase cycle, same-root-cause, and CI-failure loop limits are all fixed at five; any other
  repository-variable value fails closed.
- Stale, malformed, unbound, or head-drifted native evidence remains fail-closed.

## Security effect

This change increases review and remediation coverage without granting Codex merge,
branch-protection, workflow, or direct-main write authority. It does not enable external target
actions or paid OpenAI API use.

## Validation record

Validated from the clean `governance/exhaustive-codex-review` branch based on `main` commit
`21d1d1e`:

- `python -m compileall -q automation scripts/ci`: PASS
- `python scripts/ci/validate_automation.py`: `AUTOMATION_VALIDATION=PASS`
- `python -m ruff check automation scripts/ci tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py`: PASS
- `python -m pytest -q tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py --strict-markers`: 159 passed
- Ruby YAML parse plus Node syntax check of the `actions/github-script` body in
  `.github/workflows/ai-loop-control.yml` and `.github/workflows/ci.yml`: PASS

The Phase 0C implementation loop remains paused. Its implementation branch is not modified by this
governance pull request and must be resumed only after this change is human-reviewed and merged.
