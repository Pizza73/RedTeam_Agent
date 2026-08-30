# Base Refresh Label Permission Governance Report

## Decision and scope

The Phase loop retry on 2026-08-30 showed that the base-refresh workflow could write its exact-SHA
authorization status but could not replace pull-request labels. The correction keeps GitHub Actions
unable to call the pull-request merge endpoint: the workflow records authorization only, while the
authenticated local orchestrator performs the bounded label rollback and branch update.

No OpenAI API key or metered OpenAI API service is used.

## Input and incident evidence

- Input default-branch SHA: `424602e34fb9d629b0bf1fad2c16ee8f981a6cc0`
- PR: `https://github.com/Pizza73/RedTeam_Agent/pull/3`
- Failed run: `https://github.com/Pizza73/RedTeam_Agent/actions/runs/33311334201`
- Exact PR HEAD: `8ab811eaba39848fd2804c6e9ed815235362ac4c`
- Failure: HTTP 403 `Resource not accessible by integration`
- Rejected operation: `PUT /repos/Pizza73/RedTeam_Agent/issues/3/labels`

The workflow had already emitted its successful SHA-bound `redteam/base-refresh/...` status. The
local runner was stopped before it changed the PR branch.

## Least-privilege correction

The workflow permission block is exactly:

```yaml
contents: read
pull-requests: read
statuses: write
```

The workflow does not mutate labels and has no pull-request write permission. The local
orchestrator accepts only a successful `github-actions[bot]` status bound to the old full HEAD,
current default-branch SHA, adjacent Phase rollback and trusted prior PASS permalink. It then:

1. re-reads and compares the complete PR state;
2. replaces the labels with one exact set containing the adjacent prior Phase and
   `ai-needs-implementation`;
3. re-reads and compares the complete resulting PR state; and
4. requests the branch update with the old full HEAD as `expected_head_sha`.

Any concurrent HEAD, base, label, lifecycle or repository change fails closed. This operation does
not call the final pull-request merge endpoint.

## Regression controls

- Unit coverage verifies the exact local label request and rejects concurrent PR drift before it.
- Status parsing continues to reject untrusted creators, pending/malformed status, stale target
  base, non-adjacent Phase, wrong HEAD and a missing or mismatched prior PASS.
- Automation validation rejects workflow label mutation, `pull-requests: write`, `contents: write`,
  secrets, PR comments and final merge calls.

## Validation results

- Focused Ruff for the runner, validator and changed tests: PASS.
- Focused unit tests: PASS, 86 tests.
- Full tests: PASS, 238 tests; no skip or xfail was added.
- Branch coverage: PASS, 75% total.
- Automation validator: PASS, `AUTOMATION_VALIDATION=PASS`.
- Python `compileall`: PASS.
- YAML parse of all seven workflows: PASS.
- Dependency check: PASS, no broken requirements.
- Exact `bash scripts/ci/run_phase_gate.sh phase-0a`: FAIL at repository-wide Ruff with the
  unchanged 88 Phase 0A application findings on the governance base.
- Standalone mypy: FAIL with the unchanged 40 Phase 0A application errors on the governance base.

The governance change does not modify or suppress those application findings. PR #3 contains the
Phase 0A implementation fixes and must pass the exact gate after the bounded base refresh.

## Implementation report

- Current boundary: Phase 0A revalidation before Phase 0B.
- Input review/default-branch SHA: `424602e34fb9d629b0bf1fad2c16ee8f981a6cc0`.
- Resulting working-tree diff: one least-privilege workflow reduction, one local orchestrator
  transition, documentation alignment and regression coverage.
- Modified files: `.github/workflows/refresh-ai-loop-base.yml`,
  `automation/run_phase_loop.py`, `tests/unit/test_phase_loop.py`,
  `tests/unit/test_automation_validation.py`, `docs/requirements.md`,
  `docs/acceptance-criteria.md`, `docs/ai-development-loop.md`,
  `docs/ai-loop-runbook.md`, `docs/threat-model.md`, and the three related reports under
  `docs/review/`.
- Finding addressed: Actions label replacement failed with HTTP 403, without granting the workflow
  pull-request merge authority.
- Regression tests added: exact local label request, trusted-status transition, pre-write drift and
  post-write drift, rolled-back restart, and conflicting source/restart transition identities.
- Review finding addressed: Codex P1 `discussion_r3889395110`; the runner now requires one
  unambiguous transition identity before either label replacement or branch update.
- Remaining constraint: the local operator login must retain permission to replace PR labels and
  update the PR branch; all changes remain exact-state and exact-HEAD bound.
