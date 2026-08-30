# Pre-trigger Finding Remap Governance Report

## Current phase and authorization

- Active implementation phase: `Phase 0B: Execution Safety`
- Blocked implementation HEAD: `3ec3cbb8007b3d04e9d1a1130163693c1ea4d0cc`
- Governance base: `50a7d1d`
- User authorization: the protected AI-loop correction was explicitly approved on 2026-08-31.
- OpenAI API or other metered API use: none

## Incident evidence

After the verified Phase 0B correction was pushed, the local orchestrator created trusted review
trigger comment `5471282514` for the exact current HEAD. It then stopped with:

```text
AI_LOOP=BLOCKED: current-head Codex finding predates the trusted trigger
```

GitHub had remapped historical Codex review comment `3889834343` onto the current diff. Its live REST
representation had `commit_id` equal to the current HEAD, while `original_commit_id` remained the
prior implementation SHA `c2ec88545bc0e31dafde1e0d3d72c8ea4f46f99c`. Its creation timestamp
preceded the trusted trigger. The runner therefore treated non-authoritative historical evidence as
a current review result and could never reach the fresh post-trigger review.

## Fail-closed correction

Both independent enforcement points now apply the trusted-trigger timestamp boundary before parsing
a Codex finding's priority:

- reviewer comments at or before the exact-SHA trigger are historical and are not candidates;
- only comments after the trigger can become current P0/P1 findings;
- a post-trigger finding still requires the trusted reviewer, exact current HEAD, a post-trigger
  formal review, a retained permalink, and an owning review ID;
- malformed or unbound post-trigger findings still fail closed; and
- head synchronization during review is still rejected.

`original_commit_id` is recorded as incident evidence but is not promoted to an authorization
source. The authoritative boundary remains the trusted actor's exact phase/HEAD/base trigger and its
timestamp. No workflow permission, label, branch update, final-merge, reviewer identity, or approval
control changed.

## Resulting working-tree diff

Modified files:

- `.github/workflows/ai-loop-control.yml`
- `automation/run_phase_loop.py`
- `tests/unit/test_automation_validation.py`
- `tests/unit/test_phase_loop.py`
- `docs/review/pre-trigger-finding-remap-governance.md`

The local runner and the Phase Gate workflow now use the same pre-trigger filter. Static automation
validation also requires that workflow filter and rejects restoration of the obsolete pre-trigger
failure branch.

## Findings addressed and regression tests

Finding addressed: a GitHub-remapped historical P0/P1 comment could permanently block a fresh
SHA-bound native Codex review even though it predated the trusted trigger.

Regression tests added:

- a historical P1 whose `commit_id` is remapped to current HEAD is ignored before the trigger;
- an ambiguous historical P0/P1 body is ignored before priority parsing; and
- an unbound P1 after the trigger is rejected.

The existing current-finding, formal-review binding, stale PASS, reviewer reaction, and head-drift
tests remain enabled. No test was skipped, deleted, weakened, or marked as an expected failure.

## Validation

- Focused Ruff on changed Python files: PASS.
- Focused unit tests: PASS, `119 passed`.
- Full test suite: PASS, `282 passed`; no skips or xfails were added.
- Branch coverage: PASS, `84%` total.
- Automation validator: PASS.
- Python compileall for the changed runner/tests: PASS.
- Workflow YAML parse for all workflows: PASS.
- Mypy on the changed runner with the repository's unavailable third-party `jsonschema` stubs
  ignored: PASS. A plain standalone run stops only on that pre-existing missing-stub diagnostic.
- Embedded JavaScript parser: not available in the local environment; the changed block is covered
  by workflow static assertions and must also pass GitHub's workflow validation.

Required command executed:

```text
bash scripts/ci/run_phase_gate.sh phase-0a
```

Result: FAIL after `AUTOMATION_VALIDATION=PASS`, at the unchanged repository-wide application Ruff
baseline (`88 errors`) on the governance base. The gate did not reach its later mypy/test/coverage
steps. The governance branch does not copy or alter the Phase 0A/0B application corrections isolated
on PR #3; focused lint, full tests, and coverage were therefore run separately as recorded above.

## Remaining constraints

- This protected workflow change requires human review and manual merge; the local final-merge path
  intentionally excludes governance PRs.
- After merge, update a clean local `main` and restart the phase loop for PR #3. Because `main` will
  have advanced, the existing bounded base-refresh protocol will revalidate the appropriate prior
  phase before returning to Phase 0B.
- Phase 0C remains unauthorized until Phase 0B receives a trusted current-HEAD PASS.
