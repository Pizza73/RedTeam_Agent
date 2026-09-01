#!/usr/bin/env bash
set -euo pipefail

phase="${1:-}"
if [[ ! "$phase" =~ ^phase-(0a|0b|0c|[1-5])$ ]]; then
  echo "usage: $0 phase-0a|phase-0b|phase-0c|phase-1|...|phase-5" >&2
  exit 2
fi

test -f pyproject.toml
test -d src/redteam_agent
test -d tests

gate_tmp="$(mktemp -d)"
trap 'rm -rf "$gate_tmp"' EXIT

python - <<'PY'
import importlib

required = ["pytest", "ruff", "mypy", "coverage", "hypothesis"]
missing = []
for module in required:
    try:
        importlib.import_module(module)
    except Exception as exc:
        missing.append(f"{module}: {exc}")
if missing:
    raise SystemExit("Missing required dev dependencies:\n" + "\n".join(missing))
PY

python -m compileall -q src/redteam_agent
python scripts/ci/validate_automation.py
python scripts/ci/validate_invariant_audit.py --phase "$phase" --if-present
python -m ruff check .
python -m mypy src/redteam_agent
python -m pytest -q tests/unit --strict-markers
python -m pytest -q tests/integration --strict-markers
python -m pytest -q tests/security --strict-markers

phase_test_dir="tests/phases/${phase//-/_}"
if [[ -d "$phase_test_dir" ]]; then
  python -m pytest -q "$phase_test_dir" --strict-markers
fi

export COVERAGE_FILE="$gate_tmp/coverage"
python -m coverage erase
python -m coverage run --branch -m pytest -q tests --strict-markers --junitxml="$gate_tmp/tests.xml"
python -m coverage report --show-missing
python -m coverage xml -o "$gate_tmp/coverage.xml"

TEST_XML="$gate_tmp/tests.xml" python - <<'PY'
import os
import xml.etree.ElementTree as ET

root = ET.parse(os.environ["TEST_XML"]).getroot()
skipped = sum(int(node.attrib.get("skipped", "0")) for node in root.iter("testsuite"))
errors = sum(int(node.attrib.get("errors", "0")) for node in root.iter("testsuite"))
failures = sum(int(node.attrib.get("failures", "0")) for node in root.iter("testsuite"))
if skipped or errors or failures:
    raise SystemExit(
        f"Gate requires skipped=0, errors=0, failures=0; got "
        f"skipped={skipped}, errors={errors}, failures={failures}"
    )
PY

python -m pip check
echo "PHASE_GATE=$phase PASS"
