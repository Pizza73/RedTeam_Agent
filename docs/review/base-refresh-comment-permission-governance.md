# Base Refresh PR Comment Permission Governance Report

## Decision and scope

The approved Phase 0A revalidation loop reached the exact-SHA base-refresh workflow on 2026-08-30
and failed at its first pull-request timeline comment. This correction changes only the workflow
permission required for that existing operation:

- Change `pull-requests: read` to `pull-requests: write` in
  `.github/workflows/refresh-ai-loop-base.yml`.
- Keep `contents: read`; the workflow cannot push or update the PR branch.
- Keep `issues: write` for labels and `statuses: write` for the SHA-bound phase status.
- Do not add approval, merge, force-push, branch-protection, or repository-content write calls.

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
validations completed before the rejected write. The workflow stopped before creating the
`redteam-base-refresh` marker, changing labels, or changing phase status. The local runner was
stopped while waiting for that absent trusted marker; it did not update the PR branch.

## Regression control

`tests/unit/test_automation_validation.py` requires the refresh workflow permission block to equal:

```yaml
contents: read
issues: write
pull-requests: write
statuses: write
```

The same test continues rejecting merge API calls and `contents: write`. The exact-head update is
still performed only by the local operator through GitHub's `update-branch` endpoint after the
trusted workflow marker exists.

## Validation results

- `.venv/bin/python -m pytest -q tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py --strict-markers`
  - PASS: 68 tests
- `.venv/bin/python -m pytest -q tests --strict-markers`
  - PASS: 203 tests
- `.venv/bin/python -m ruff check automation scripts/ci tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py`
  - PASS
- `.venv/bin/python scripts/ci/validate_automation.py`
  - PASS: `AUTOMATION_VALIDATION=PASS`
- Ruby YAML parse of all seven `.github/workflows/*.yml` files
  - PASS
- `bash scripts/ci/run_phase_gate.sh phase-0a`
  - FAIL at repository-wide Ruff with the unchanged 88 Phase 0A application findings on the
    governance base; the script does not reach later gate steps

The permission correction does not change or suppress those application findings. PR #3 contains
the Phase 0A implementation fixes and must pass the exact gate after the base refresh.

## Required handoff

This protected workflow change requires human review and manual merge. After merge, update the
clean local `main` checkout and restart `automation/run_phase_loop.py` for PR #3. The workflow can
then retry the unchanged exact-SHA request; Phase 0A must pass again on the refreshed head before
Phase 0B is authorized.
