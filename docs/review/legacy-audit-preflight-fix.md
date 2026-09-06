# Legacy audit preflight / CI failure handoff correction

Date: 2026-09-06. Scope: explicitly approved governance correction, not product implementation.

## Input and authority

- Governance base: `6aeff1b0f7cfccd38a1f567f6794714ff149749c` (merged PR #40).
- Product Phase: Phase 0C, still stopped. Inspected input HEAD:
  `350560d490dd1ed45fe6d14f07934c3ce6c0845c` on PR #3.
- Input review / blocking gate: the latest Phase 0C recurrence gate remains
  [issuecomment-5515692085](https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5515692085).
  Its reviewed SHA is `ae09f40f6b593060d060cfb9a5090e0de4e2875d`; the newer input HEAD above is
  the incorporated governance-refresh output, not a newly reviewed implementation.
  This governance task has no new product implementation request or formal-review input.
- The user explicitly approved a separate Governance PR to repair legacy audit compatibility and
  CI failure-handoff read permission. No Design Approval, Resume, Phase transition or merge is issued.

## Findings addressed and changes

1. The refreshed PR's [quality failure](https://github.com/Pizza73/RedTeam_Agent/actions/runs/34035762291)
   applied the new `secret-plaintext-boundary.stateful=true` rule to a report recorded under the old
   policy. Product work was forbidden until Design Approval, but approval required successful CI.
   The existing historical-read requirement (LOOP-032) was therefore not implemented completely.
2. `ci-failure-handoff` could not read `automation/phase-plan.json` from the default branch: its
   job-level permission declaration omitted `contents: read`, resulting in HTTP 403.
3. Restoring that read must not let a stopped PR receive a fresh CI fix request. The handoff now
   loads the current open, same-repository, exact-HEAD PR and checks the Phase and stop latch before
   request writes, including another check after the lifecycle-label write.

The new explicit `--if-present --historical-preflight` mode accepts only an unchanged committed
legacy report with a proper-ancestor input, unchanged referenced evidence/application source and
the same legacy policy at the input and report revisions. It applies the original stateful flags
without rewriting the audit or inventing test evidence. The current required family set remains
mandatory. Missing or changed history/evidence fails closed. New-policy reports cannot downgrade by
deleting the strategy block; any present strategy is checked against current policy.

The result is `PREFLIGHT_ONLY`, not current-policy audit PASS or authorization. This mode cannot be
combined with trusted-request/output certification. The ordinary validator, new-request strategy,
Review Ready, current-HEAD checks, checkpoint and dedicated Design Approval requirements remain.

The workflow gains only job-scoped `contents: read`. It gains no contents-write/merge capability,
does not use `pull_request_target`, and does not export credentials. API read failure or PR drift
does not issue an implementation request. A stop observed between writes suppresses the request;
GitHub writes are not transactional, so the existing conservative stop latch and Runner's fresh
authority revalidation remain mandatory even if a lifecycle projection was partially written.

## Modified files / resulting diff

- `scripts/ci/validate_invariant_audit.py`: bounded historical preflight with Git/evidence checks;
  strict current-policy behavior remains the default.
- `scripts/ci/run_phase_gate.sh`: explicitly select non-authorizing preflight; retain every existing
  compile, validation, lint, type, test, coverage, zero-skip and dependency check.
- `.github/workflows/ci.yml`: minimum read permission and current-state/stop guards for failure handoff.
- `tests/unit/test_automation_validation.py`: 32 additional regression cases (including parametrized
  cases); existing tests are retained.
- `docs/acceptance-criteria.md`, `docs/ai-development-loop.md`, `docs/ai-loop-runbook.md`: describe
  the historical/current distinction and failure-handoff requirements.
- `docs/review/legacy-audit-preflight-fix.md`: this report.

No application source, invariant policy, phase plan, historical audit JSON, dependency, Design
Approval workflow, retry limit or merge permission is changed.

## Regression evidence

- An unchanged historical report validates with the identical canonical digest; default validation
  still rejects its missing current stateful evidence.
- Historical mode cannot certify an expected request/output or replace required strategy evidence.
- Changed/recommitted audits, tracked/untracked application changes, changed/missing/outside-repo
  evidence, duplicate JSON keys and unknown fields are rejected.
- The original policy's stateful requirement is still enforced; a new strategy uses the current
  stateful requirement even in preflight. Removing strategy from a new-policy report is rejected.
- The actual workflow script runs against fake GitHub APIs for normal handoff, existing/late stop,
  stop after label write, HEAD/Phase drift, closed/fork PR, read denial, duplicate request and retry
  exhaustion. No live AI/C2/MCP/target operation is used by these tests.

## Validation

Commands used the repository `.venv` (Python 3.13.14), with Node.js available on PATH:

```bash
export PATH="/home/kali/RedTeam_Agent/.venv/bin:/home/kali/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin:$PATH"
python -m pytest -q tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py --strict-markers
python -m ruff check automation scripts/ci tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py
python -m compileall -q automation scripts/ci
python scripts/ci/validate_automation.py
git diff --check
```

Results: **297 governance tests passed**; scoped lint, compile, automation validation and whitespace
checks passed. Formatting errors found during the first two lint iterations were corrected; no
tests, safety assertions or requirements were weakened to obtain a pass.

An additional, non-gate check, `python -m mypy scripts/ci/validate_invariant_audit.py`, reports the
existing missing `jsonschema` typing stubs (`import-untyped`). The locked dependencies were not
changed for this task. This does not affect the required application Mypy check below; standalone
strict typing of the governance script remains unverified. A diagnostic run with
`--follow-imports=silent --ignore-missing-imports` passed, but is not reported as strict typing PASS.

A detached local clone of PR #3's exact input HEAD was created at
`/tmp/redteam-governance-preflight.2WA2qG`. Only the four changed validator/gate/workflow/test files
were overlaid with this governance diff; the application and historical audit were unchanged.
The validator was also run directly from the governance checkout against this clone:

```bash
python scripts/ci/validate_invariant_audit.py --repo-root /tmp/redteam-governance-preflight.2WA2qG --phase phase-0c --if-present
python scripts/ci/validate_invariant_audit.py --repo-root /tmp/redteam-governance-preflight.2WA2qG --phase phase-0c --if-present --historical-preflight
```

The first command reproduced `BLOCKED: affected stateful family secret-plaintext-boundary lacks
property/state-machine evidence`. The second returned:

```text
INVARIANT_AUDIT=PREFLIGHT_ONLY:cd190fd83e11493abeb794e7c9f869d687232246af6d9a056d62ba6be544cb48
```

The complete required gate was then executed in that detached clone:

```bash
env PATH="/home/kali/RedTeam_Agent/.venv/bin:/home/kali/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin:$PATH" PYTHONPATH="/tmp/redteam-governance-preflight.2WA2qG/src:/tmp/redteam-governance-preflight.2WA2qG" bash scripts/ci/run_phase_gate.sh phase-0c
```

Result: **`PHASE_GATE=phase-0c PASS` (local deterministic validation only)**.

- Compile, automation validation, preflight and full-tree Ruff: PASS.
- Mypy: PASS, 81 application source files.
- Unit: 336 passed; integration: 7 passed; security: 240 passed.
- Branch-enabled coverage run: 583 passed; report total 80% (9,936 statements, 3,004 branches).
- JUnit zero-skip/error/failure check and `pip check`: PASS.

This exercises the cumulative implementation tree rather than the older application snapshot on
the governance/default branch. It does not certify the existing product against the new design or
replace independent Phase review. The GitHub Python 3.12/3.14 governance checks must pass on the
published Governance PR HEAD before human review/merge.

## Remaining constraints / next step

The real PR #3 remains stopped on the inspected HEAD; its failing CI is not relabeled successful.
The workflow's real-token permission path will only be available after human merge and authorized
incorporation; local fake-API tests are not a live GitHub permission grant.

After human review/merge, use the existing exact-HEAD Base Refresh and checkpoint, wait for all
required checks on the new PR #3 HEAD, then obtain the dedicated Design Approval. Only its new
single-use request can resume Phase 0C implementation. Do not use generic Resume, manually change
the stop latch, fake old audit evidence, or treat this Governance PR as a Phase PASS.
