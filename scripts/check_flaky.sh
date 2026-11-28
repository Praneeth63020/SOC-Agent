#!/usr/bin/env bash
# Run the full offline test suite N times (default 3) and keep each junit file for the flaky-test check in
# docs/test-report.md (scripts/make_test_report.py compares the outcome of every test across the runs).
#   scripts/check_flaky.sh [N]
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-$([[ -x .venv/bin/python ]] && echo .venv/bin/python || echo python3)}"
N="${1:-3}"
mkdir -p reports
rm -f reports/junit-run*.xml
status=0
for i in $(seq 1 "$N"); do
  echo "== full suite, run $i of $N"
  "$PY" -m pytest -q -p no:cacheprovider --junitxml="reports/junit-run$i.xml" | tail -1 || status=1
done
exit $status
