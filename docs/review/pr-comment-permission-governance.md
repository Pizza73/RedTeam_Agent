# Phase Gate PR Comment Permission Governance Report

## Decision

The human operator approved this protected-workflow change on 2026-08-30 after the first live
native-evidence phase-gate dispatch failed. The change is limited to the `Record AI Phase Review`
workflow:

- Change `pull-requests: read` to `pull-requests: write`.
- Keep `contents: read`; the workflow cannot push implementation changes.
- Keep the repository setting that allows Actions to approve pull requests disabled.
- Do not add merge or approval API calls.

No OpenAI API key or metered OpenAI API call is used.

## Incident evidence

- Failed run: https://github.com/Pizza73/RedTeam_Agent/actions/runs/33283518096
- Phase: `phase-0a`
- Reviewed head: `8ab811eaba39848fd2804c6e9ed815235362ac4c`
- Workflow revision: `02c32c02c518e1a28b2a70065b11bef4ab6e21ca`
- Failure: `403 Resource not accessible by integration`
- Rejected operation: `POST /repos/Pizza73/RedTeam_Agent/issues/3/comments`

The job log confirmed that native Codex evidence validation completed before the first state
mutation. The token had `Issues: write` but only `PullRequests: read`. GitHub rejected creation of
the trusted phase record on the pull request. The workflow stopped before creating a phase record,
changing labels, or advancing to Phase 0B.

GitHub documents pull-request write permission as an accepted permission set for creating a
regular pull-request timeline comment:
https://docs.github.com/en/rest/issues/comments#create-an-issue-comment.

## Regression control

`tests/unit/test_automation_validation.py` now requires the phase-gate workflow permission block
to equal the following scoped set:

```yaml
checks: read
contents: read
issues: write
pull-requests: write
statuses: write
```

The same test rejects the presence of known pull-request merge or approval calls in this workflow.
The operator-restricted actor check, full-SHA native review evidence validation, bounded retry
controls, manual final merge, and `can_approve_pull_request_reviews=false` repository setting are
unchanged.

## Validation results

```text
.venv/bin/python -m pytest -q \
  tests/unit/test_automation_validation.py \
  tests/unit/test_governance_check.py
24 passed in 0.35s

.venv/bin/python scripts/ci/validate_automation.py
AUTOMATION_VALIDATION=PASS

.venv/bin/python -m ruff check tests/unit/test_automation_validation.py
All checks passed!

.venv/bin/python -m mypy --ignore-missing-imports \
  tests/unit/test_automation_validation.py
Success: no issues found in 1 source file

ruby -e 'require "yaml"; YAML.parse_file(".github/workflows/ai-loop-control.yml"); \
  puts "YAML_PARSE=PASS"'
YAML_PARSE=PASS

.venv/bin/python -m pytest -q
183 passed in 2.72s

bash scripts/ci/run_phase_gate.sh phase-0a
AUTOMATION_VALIDATION=PASS
FAIL: repository-wide Ruff reported 88 pre-existing errors on the default-branch Phase 0A tree
```

The exact phase gate was run as required. Its Ruff failure is inherited from `main`; the corrected
Phase 0A application tree remains isolated in implementation PR #3. This governance change does
not copy application fixes into a protected-control branch or weaken the gate.

The live Phase 0A record must not be retried until this protected change is manually reviewed and
merged to the default branch.
