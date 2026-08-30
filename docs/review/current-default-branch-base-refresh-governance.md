# Current Default-Branch Base Refresh Governance Report

## Scope

- Current phase boundary: Phase 0A revalidation before Phase 0B
- Governance base SHA: `833756bda51c314f2bfd0a4e862097fe800d28ea`
- Input Phase 0A review/PASS SHA: `8ab811eaba39848fd2804c6e9ed815235362ac4c`
- Input PASS evidence:
  `https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5465826440`
- Request type: explicitly approved governance correction
- Application behavior changed: no
- Final PR merge automation added: no

## Incident evidence and root cause

The Pulls API state for implementation PR #3 reported:

- PR head SHA: `8ab811eaba39848fd2804c6e9ed815235362ac4c`
- `base.sha`: `2e50db4dbcc127d87237c212b909edb499c1bd34`
- Current `main` SHA: `833756bda51c314f2bfd0a4e862097fe800d28ea`
- Compare status from PR head to current `main`: diverged, ahead by 7 and behind by 2
- Merge base: `2e50db4dbcc127d87237c212b909edb499c1bd34`

The runner and base-refresh workflow treated `pr.base.sha` as the current default-branch tip. For
this long-lived PR it represented the stale merge base instead. The runner therefore evaluated the
wrong comparison and reached the old SHA-bound Codex blocker before authorizing the required base
refresh.

## Controls implemented

- The local runner fetches the current default-branch commit independently from the Pulls API.
- Startup binds the clean local governance checkout to that exact default-branch SHA. If `main`
  changes while the loop is running, the loop stops and requires a clean update and restart.
- Base-advance detection, refresh authorization, stale-refresh reauthorization, and workflow
  inputs use the independently fetched current default-branch SHA.
- The refresh workflow verifies `target_base_sha` directly against the current default-branch
  commit and no longer requires the stale Pulls API `base.sha` to equal it.
- A refreshed Phase 0A review uses the target SHA from trusted `redteam/base-refresh/...` commit
  status evidence only when both the pre-refresh PR head and the refresh target are exact ancestors
  of the reviewed head.
- The GitHub phase-gate workflow performs the same two ancestor checks before accepting the
  refreshed Phase 0A review base.
- Refresh statuses bind the old commit, adjacent `phase-0b` to `phase-0a` rollback, full lowercase
  target SHA, fixed description, workflow-bot creator, success state and prior PASS permalink.
  Malformed, unrelated, or stale history fails closed.
- The final merge API remains absent. Final merge remains human-only.

## Resulting working-tree diff

Modified or added files:

- `.github/workflows/ai-loop-control.yml`
- `.github/workflows/refresh-ai-loop-base.yml`
- `automation/run_phase_loop.py`
- `tests/unit/test_automation_validation.py`
- `tests/unit/test_phase_loop.py`
- `docs/review/current-default-branch-base-refresh-governance.md`

No file under `src/redteam_agent/`, no phase specification, no safety invariant, no acceptance
criterion, and no external-action adapter changed.

## Findings addressed and regression tests

- Pulls API `base.sha` is not used as the current default-branch tip for refresh decisions.
- A default-branch race after runner startup raises a typed prerequisite error.
- Phase 0A review selects the trusted refreshed base rather than the stale PR base SHA.
- A refreshed head unrelated to either the old head or target base is rejected.
- Codex P1 `https://github.com/Pizza73/RedTeam_Agent/pull/7#discussion_r3888729311`
  found that `main` could advance after the local runner check but before the dispatched phase-gate
  execution. The gate now re-fetches the live PR and default branch immediately before recording
  the result, and the local evaluator rejects a refresh target that is no longer current.
- Initial, non-refreshed Phase 0A review retains the original PR base behavior.
- Exact merge-base, behind-count, and compare-status semantics are tested for ancestor checks.
- Workflow tests require refreshed-base ancestry controls and reject the obsolete equality check.

## Validation results

- `.venv/bin/python -m pytest -q tests/unit/test_phase_loop.py tests/unit/test_automation_validation.py tests/unit/test_governance_check.py --strict-markers`
  - PASS: 68 tests
- `.venv/bin/python -m pytest -q tests/unit/test_phase_loop.py tests/unit/test_automation_validation.py --strict-markers`
  - PASS: 51 tests; exact Codex P1 retest request
- `.venv/bin/python -m pytest -q tests/unit --strict-markers`
  - PASS: 91 tests
- `.venv/bin/python -m pytest -q tests/integration --strict-markers`
  - PASS: 4 tests
- `.venv/bin/python -m pytest -q tests/security --strict-markers`
  - PASS: 107 tests
- Phase-specific test directory `tests/phases/phase_0a`
  - Not present; `scripts/ci/run_phase_gate.sh` conditionally skips it
- Branch coverage run over `tests`
  - PASS: 203 tests; 84% total branch coverage
- `.venv/bin/python -m ruff check automation scripts/ci tests/unit/test_phase_loop.py tests/unit/test_automation_validation.py tests/unit/test_governance_check.py`
  - PASS
- `.venv/bin/python scripts/ci/validate_automation.py`
  - PASS: `AUTOMATION_VALIDATION=PASS`
- Ruby YAML parse of all seven `.github/workflows/*.yml` files
  - PASS
- Tree-sitter JavaScript parse of the two changed workflow scripts
  - PASS
- `.venv/bin/python -m pip check`
  - PASS: no broken requirements
- `bash scripts/ci/run_phase_gate.sh phase-0a`
  - FAIL at repository-wide Ruff with the 88 pre-existing Phase 0A implementation findings on the
    governance base; later gate commands are not reached
- `.venv/bin/python -m mypy src/redteam_agent`
  - FAIL with the known 40 errors in 16 application files on the governance base

The full gate findings are neither changed nor suppressed in this governance correction. The
refreshed implementation PR combines the Phase 0A application fixes with current governance and
must pass the exact gate and independent review on its resulting SHA.

## Remaining constraints

- Governance pull request:
  `https://github.com/Pizza73/RedTeam_Agent/pull/7`
- GitHub creates the initial `opened` event before a separately requested label is guaranteed to
  be present. The follow-up documentation commit was pushed only after `governance-change` was
  confirmed, so its `synchronize` event is the current-head CI evidence.
- This protected workflow change requires human review and a manual merge.
- After merge, the operator must update a clean local `main` checkout and restart the runner for
  PR #3.
- The runner may call only the SHA-bound GitHub `update-branch` endpoint. Conflict resolution,
  force-push, history rewrite, branch-protection change, and final PR merge are not automated.
- Phase 0B remains unauthorized until the refreshed PR head receives a new trusted Phase 0A PASS.
