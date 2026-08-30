# Maximal Incorporated Base-refresh Selection

## Current phase and trigger

- Current implementation phase: Phase 0A revalidation.
- Reviewed PR head observed during diagnosis:
  `323753f51bb571366bbf08123b42840a81491655`.
- Latest default branch incorporated by that head:
  `1f4ccb10ba892127b4d39492e45c9f257e991f66`.
- Incorrect review base selected before this fix:
  `79c31c966b81267b32045c4726db9ab716f49af8`.

## Finding addressed

The local runner gathered trusted refresh statuses from every historical Phase
0A PASS SHA and then selected the last ancestor-compatible record based on
collection order. Candidate PASS SHAs were sorted lexically, so an older
refresh could appear last even though a later trusted transition had produced
the current reviewed HEAD. The Gate would accept the same older supplied base
because it checked only that the chosen old HEAD and target base were
ancestors.

This did not omit code from the Codex diff—the older base made the diff larger—
but it failed to bind review evidence to the unique transition that most
recently advanced both the implementation head and its trusted base.

## Fix

Both the local runner and the Gate workflow now:

1. validate every trusted base-refresh record;
2. retain only records whose old HEAD and target base are both ancestors of
   the exact reviewed HEAD;
3. deduplicate identical records;
4. order candidates by paired ancestry: a candidate is superseded only when
   both its old HEAD and target base are ancestors of another candidate and at
   least one component advances; and
5. require exactly one maximal candidate.

No timestamp, REST response order, SHA lexical order, or live default-branch
substitution is used. Multiple incomparable maxima are rejected as ambiguous.

## Regression tests

- A later old-HEAD/target-base pair wins even when the older record appears
  last in the input list.
- Two incorporated but incomparable refresh pairs fail closed.
- Static workflow validation requires the shared ancestor helper and the
  unique-maximal guard.

## Validation results

- `.venv/bin/python -m pytest -q tests/unit/test_phase_loop.py
  tests/unit/test_automation_validation.py`: PASS, 96 tests.
- `.venv/bin/python -m pytest -q tests --strict-markers`: PASS, 248 tests.
- branch coverage: PASS, 84% total.
- focused Ruff for the runner and regression tests: PASS.
- automation validator: `AUTOMATION_VALIDATION=PASS`.
- compileall and dependency consistency: PASS.
- `bash scripts/ci/run_phase_gate.sh phase-0a`: automation validation passed,
  then the Gate stopped on 88 Ruff findings in unchanged Phase 0A application
  files already corrected on PR #3.
- application mypy: 40 findings in the same unchanged Phase 0A application
  tree; focused runner mypy is additionally blocked by the existing missing
  `jsonschema` stub package.

## Safety constraints

- Workflow permissions are unchanged.
- Final merge authority is unchanged and remains local-only.
- No labels or branches are changed by the Gate workflow.
- No OpenAI API, secret, C2, MCP, or external-target operation is introduced.
