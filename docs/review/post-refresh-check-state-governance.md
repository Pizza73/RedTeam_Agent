# Post-Refresh Check-State Governance Report

## Incident

After pull request 3 reached refreshed HEAD `fb4280bf136706ebd07643d53bf65736180bd32d`,
three required checks had passed and `quality` was still running. `check_state()` correctly returned
`waiting`, but the two post-refresh Resume branches compared that result with the unused value
`pending`. The runner therefore treated an in-progress check as a deterministic failure and stopped.

## Correction

Both post-refresh branches now use the single existing `waiting` state emitted by `check_state()`.
The normal blocked Resume path and the Design Stop path return to polling while any required check is
missing or incomplete. A completed non-success check remains fail-closed, and Resume still requires
all four exact current-HEAD checks to succeed.

## Regression coverage

- an ordinary checkpointed blocker waits without dispatching Resume while checks are running;
- the same state dispatches exactly one Resume after checks succeed; and
- a Design Stop waits without dispatching generic Resume while checks are running.

## Validation

- `.venv/bin/python -m pytest -q`: PASS, 352 tests.
- `.venv/bin/python scripts/ci/validate_automation.py`: PASS.
- focused Ruff and `git diff --check`: PASS.
- exact `bash scripts/ci/run_phase_gate.sh phase-0c`: stops at the unchanged 88 Ruff findings on
  the `main` application snapshot; this governance fix neither edits nor suppresses them.
