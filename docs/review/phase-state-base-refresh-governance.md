# Phase State and Base Refresh Governance Report

> Historical note: the workflow-side label transition described below was superseded after live
> permission validation. The current design is recorded in
> `docs/review/base-refresh-label-permission-governance.md`: the workflow writes exact-SHA status
> evidence and the local orchestrator performs the fully revalidated label rollback.

## Scope

- Current boundary: Phase 0A -> Phase 0B governance transition
- Governance base SHA: `85afc9fef28bc2e03f6ba3cacb982f147aac74e8`
- Input Phase 0A review/PASS SHA: `8ab811eaba39848fd2804c6e9ed815235362ac4c`
- Input PASS evidence:
  `https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5465826440`
- Request type: explicitly approved governance change
- Application behavior changed: no
- Final PR merge automation added: no

## Findings addressed

1. `docs/implementation-status.md` was both a static default-branch snapshot and an active Phase
   authority. It conflicted with the SHA-bound Phase 0A PASS and correctly caused Codex to block
   Phase 0B.
2. The long-lived implementation PR could not safely incorporate later governance changes without
   manual branch manipulation and without explicitly invalidating the old Phase PASS.
3. The local runner waited indefinitely after a SHA-bound Codex implementation `BLOCKED` response.
4. A default-branch change racing a previously authorized refresh could otherwise leave the runner
   waiting on stale evidence.

## Controls implemented

- Active Phase authority now requires the exact Phase label, workflow-authored current-HEAD
  implementation request, and adjacent prior-Phase PASS. The status document remains bootstrap
  information and cannot relax requirements or safety controls.
- `Prepare AI Loop Base Refresh` verifies the configured operator, same-repository PR, exact old
  HEAD, current default-branch SHA, default-branch advancement, trusted current implementation
  request, adjacent prior PASS, and strict marker fields.
- The workflow moves the label back exactly one Phase and records a `redteam-base-refresh` marker.
- The local runner accepts that marker only from `github-actions[bot]` and calls only GitHub's
  `update-branch` endpoint with `expected_head_sha`.
- A new default-branch advancement during the handoff triggers bounded reauthorization for the new
  base SHA; it does not broaden an old authorization.
- All PASS evidence for the old PR HEAD becomes stale. CI and independent review must pass again
  for the rolled-back Phase on the resulting HEAD.
- A reviewer-authored `## BLOCKED` result is acted on only after an exact local implementation
  trigger and only when it contains the same Phase and full SHA.
- The final PR merge endpoint remains absent and final merge remains human-only.

## Resulting working-tree diff

Governance, automation, documentation, and regression tests only. No files under
`src/redteam_agent/`, no external adapter, no target action, and no credential handling changed.

Modified or added files:

- `.github/prompts/implement.md`
- `.github/workflows/refresh-ai-loop-base.yml`
- `AGENTS.md`
- `automation/chatgpt-event-task-prompt.md`
- `automation/project-settings.yml`
- `automation/run_phase_loop.py`
- `docs/acceptance-criteria.md`
- `docs/ai-development-loop.md`
- `docs/ai-loop-runbook.md`
- `docs/implementation-status.md`
- `docs/requirements.md`
- `docs/threat-model.md`
- `tests/unit/test_automation_validation.py`
- `tests/unit/test_phase_loop.py`
- `docs/review/phase-state-base-refresh-governance.md`

## Regression tests added

- Adjacent-Phase, exact-head, exact-base and unknown/stale base-refresh evidence validation.
- Current-HEAD Codex `BLOCKED` detection and stale-SHA rejection.
- Base advancement detection only before current-Phase implementation.
- Stale refresh reauthorization when `main` advances again.
- Exact `expected_head_sha` update-branch request construction.
- Workflow permission, strict-marker, SHA-binding and final-merge-API absence assertions.

## Validation results

- `.venv/bin/python -m pytest -q tests/unit/test_phase_loop.py tests/unit/test_automation_validation.py tests/unit/test_governance_check.py --strict-markers`
  - PASS: 59 tests
- `.venv/bin/python -m pytest -q tests/unit --strict-markers`
  - PASS: 83 tests after the final regression test was added (82 passed on the preceding run)
- `.venv/bin/python -m pytest -q tests/integration --strict-markers`
  - PASS: 4 tests
- `.venv/bin/python -m pytest -q tests/security --strict-markers`
  - PASS: 107 tests
- `COVERAGE_FILE=/tmp/redteam-governance-coverage .venv/bin/python -m coverage run --branch -m pytest -q tests --strict-markers`
  - PASS: 194 tests
- `COVERAGE_FILE=/tmp/redteam-governance-coverage .venv/bin/python -m coverage report --show-missing`
  - PASS: 84% total branch coverage report generated
- `.venv/bin/python -m ruff check automation scripts/ci tests/unit/test_phase_loop.py tests/unit/test_automation_validation.py tests/unit/test_governance_check.py`
  - PASS
- `.venv/bin/python scripts/ci/validate_automation.py`
  - PASS
- `.venv/bin/python -m compileall -q automation scripts/ci src/redteam_agent`
  - PASS
- `ruby -e "require 'yaml'; Dir['.github/workflows/*.yml'].each { |path| YAML.load_file(path) }"`
  - PASS
- Tree-sitter parse of the embedded JavaScript in
  `.github/workflows/refresh-ai-loop-base.yml`
  - PASS
- Temporary QuickJS execution of the workflow strict JSON parser with whitespace, numeric fields,
  repeated keys in separate array objects, and a duplicate key in one nested object
  - PASS: valid structure accepted and nested duplicate rejected
- `.venv/bin/python -m pip check`
  - PASS
- `bash scripts/ci/run_phase_gate.sh phase-0a`
  - FAIL at repository-wide Ruff with 88 pre-existing Phase 0A implementation findings on the
    governance base; the script therefore did not reach Mypy/tests/coverage.
- `.venv/bin/python -m mypy src/redteam_agent`
  - FAIL with the known 40 errors in 16 application files on the governance base.

The full Phase gate failures are not changed or suppressed here. PR #3 contains the reviewed Phase
0A fixes; after base refresh, that combined HEAD must independently re-run and pass the exact gate.

## Remaining constraints

- Governance pull request: `https://github.com/Pizza73/RedTeam_Agent/pull/6`
- Its initial `opened` CI event was created before `gh pr create --label governance-change`
  completed applying the label, so run `33285693925` correctly failed with `PR_LABELS_JSON: []`.
  This documentation commit creates a `synchronize` event after the label is present; only that
  current-HEAD run is eligible evidence.
- The governance PR must be manually reviewed and merged because the repository plan has no
  server-enforced branch protection and automated final merge is prohibited.
- After merge, the operator must update a clean local `main` checkout and restart the runner.
- GitHub may reject branch update if the exact expected HEAD changed or the branches conflict. The
  runner fails closed; it does not force-push or resolve semantic conflicts automatically.
- Phase 0B remains unauthorized until the refreshed PR HEAD obtains a new Phase 0A PASS.
