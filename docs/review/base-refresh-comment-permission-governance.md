# Base Refresh PR Comment Permission Governance Report

## Decision and scope

The approved Phase 0A revalidation loop reached the exact-SHA base-refresh workflow on 2026-08-30
and failed at its first pull-request timeline comment. GitHub required `pull_requests=write` for that
operation. An initial correction granted that permission, but Codex P1
`https://github.com/Pizza73/RedTeam_Agent/pull/8#discussion_r3888777583` correctly identified that
the permission also authorizes GitHub's PR merge endpoint.

The final correction does not accept that broader authority:

- Retain `pull-requests: read` in `.github/workflows/refresh-ai-loop-base.yml`.
- Replace the workflow-authored PR comment marker with a workflow-authored commit status under the
  exact context `redteam/base-refresh/<from-phase>/<revalidation-phase>/<target-base-sha>`.
- Bind that success status to the old full PR HEAD, a fixed description, the workflow-bot creator,
  and the trusted prior PASS permalink in `target_url`.
- Keep `issues: write` only for the existing Phase-label rollback and `statuses: write` for evidence
  and the SHA-bound phase status.
- Keep `contents: read`; do not add approval, merge, force-push, branch-protection, secret, or
  repository-content write capabilities.

No OpenAI API key or metered OpenAI API call is used.

## Incident evidence

- Failed run: `https://github.com/Pizza73/RedTeam_Agent/actions/runs/33299335781`
- Workflow revision: `7cd9855341d72f287f5e80e22289a20803519274`
- PR: `https://github.com/Pizza73/RedTeam_Agent/pull/3`
- Exact input head: `8ab811eaba39848fd2804c6e9ed815235362ac4c`
- Exact refresh target: `7cd9855341d72f287f5e80e22289a20803519274`
- Prior PASS evidence:
  `https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5465826440`
- Failure: HTTP 403 `Resource not accessible by integration`
- Rejected operation: `POST /repos/Pizza73/RedTeam_Agent/issues/3/comments`
- GitHub response accepted permissions: `issues=write; pull_requests=write`

All request, actor, PR, default-branch, Phase, prior PASS, implementation request, and exact-SHA
validations completed before the rejected write. The workflow stopped before creating trusted
refresh evidence, changing labels, or changing phase status. The local runner was stopped while
waiting for that absent evidence; it did not update the PR branch.

## Regression control

`tests/unit/test_automation_validation.py` requires the refresh workflow permission block to equal:

```yaml
contents: read
issues: write
pull-requests: read
statuses: write
```

The test rejects `pull-requests: write`, secrets, PR comment creation, merge API calls and
`contents: write`. Unit tests reject untrusted, pending, malformed, stale, unrelated and
prior-PASS-unbound status evidence. The exact-head update is still performed only by the local
operator through GitHub's `update-branch` endpoint after trusted status evidence exists.

## Validation results

- `.venv/bin/python -m pytest -q tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py --strict-markers`
  - PASS: 74 tests
- `.venv/bin/python -m pytest -q tests --strict-markers`
  - PASS: 209 tests
- `REDTEAM_COVERAGE_FILE=/tmp/redteam-status-evidence-coverage .venv/bin/python -m coverage run --source=automation,src -m pytest -q`
  - PASS: 209 tests; total coverage 74%
- `.venv/bin/python -m ruff check automation scripts/ci tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py`
  - PASS
- `.venv/bin/python scripts/ci/validate_automation.py`
  - PASS: `AUTOMATION_VALIDATION=PASS`
- Ruby YAML parse of all seven `.github/workflows/*.yml` files
  - PASS
- Tree-sitter JavaScript parse of both changed workflow script blocks
  - PASS
- `git diff --check`
  - PASS
- `bash scripts/ci/run_phase_gate.sh phase-0a`
  - FAIL at repository-wide Ruff with the unchanged 88 Phase 0A application findings on the
    governance base; the script does not reach later gate steps

The permission correction does not change or suppress those application findings. PR #3 contains
the Phase 0A implementation fixes and must pass the exact gate after the base refresh.

## Required handoff

- Governance pull request: `https://github.com/Pizza73/RedTeam_Agent/pull/8`
- The follow-up documentation commit is pushed after confirming the `governance-change` label, so
  its `synchronize` event is the current-head CI evidence rather than the unlabeled `opened` event.
This protected workflow change requires human review and manual merge. After merge, update the
clean local `main` checkout and restart `automation/run_phase_loop.py` for PR #3. The workflow can
then retry the unchanged exact-SHA request; Phase 0A must pass again on the refreshed head before
Phase 0B is authorized.
