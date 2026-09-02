# Base Refresh Stop-Latch Permission Governance Report

## Incident

The confirmation run for the already-applied Phase 0C base refresh failed before publishing its
checkpoint. The workflow attempted to add `ai-loop-blocked` to pull request 3 with a token that had
`issues: write` but only `pull-requests: read`. GitHub rejected the PR-label mutation with HTTP 403
`Resource not accessible by integration`.

## Decision

Do not grant `pull-requests: write` to the base-refresh workflow. That permission would broaden the
GitHub Actions capability beyond status publication and conflict with the invariant that Actions
cannot merge the implementation pull request.

The trusted local orchestrator now owns both forms of exact label projection:

1. after a blocked refresh authorization status is verified, it restores `ai-loop-blocked` and
   removes stale lifecycle labels before requesting the exact-HEAD branch update; and
2. for an older two-parent refresh that was already applied, it verifies the Gate, prepared status,
   parents, target base and current HEAD, restores the same projection, then requests checkpoint
   confirmation.

Before and after either local label write, the runner re-reads the exact PR state and revalidates the
trusted transition evidence. Drift fails closed. The workflow retains only `contents: read`,
`pull-requests: read` and `statuses: write`; confirmation requires the restored stop latch and only
publishes the SHA-bound checkpoint.

## Regression coverage

- a prepared blocked refresh restores the stop latch before any branch update;
- a prior-PASS refresh is not mistaken for a blocked refresh;
- an already-applied blocked refresh restores the latch before confirmation; and
- PR drift after the local label write fails closed; and
- automation validation rejects label mutation and write permissions in the workflow.

## Operational evidence

- Failed run: `https://github.com/Pizza73/RedTeam_Agent/actions/runs/33671520754`
- PR HEAD: `6e5fecd57fd51644adbffa1f6d76dac073d59748`
- Failure occurred before any PR label changed or checkpoint was published.

## Validation

- `.venv/bin/python -m pytest -q`: PASS, 352 tests.
- `.venv/bin/python scripts/ci/validate_automation.py`: PASS.
- focused Ruff for the runner and changed tests: PASS.
- focused mypy with missing third-party imports ignored: PASS.
- `git diff --check`: PASS.
- exact `bash scripts/ci/run_phase_gate.sh phase-0c`: stops at the unchanged 88 Ruff findings in
  the application snapshot on `main`; the Phase 0C implementation branch contains that later
  application work, while this governance change neither edits nor suppresses it.
