#!/usr/bin/env bash
# Clean-room verification: build the submission zip, extract it into an empty temporary folder, create a new venv,
# install, then run the secret scan, the full test suite, the scenario matrix (mock), the demo (no .env there, so
# it falls back to the MOCK LLM) and verify-audit. Writes reports/cleanroom.json for docs/test-report.md.
#   scripts/verify_clean_room.sh [--worktree]      (needs network for pip; never calls NVIDIA)
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
BASE_PY="${PYTHON:-}"
for c in python3.11 python3.12 python3.13; do [[ -z "$BASE_PY" ]] && command -v "$c" >/dev/null && BASE_PY=$c; done
[[ -n "$BASE_PY" ]] || BASE_PY=python3
scripts/package_submission.sh "${1:-}" > dist/package.log 2>&1 || { cat dist/package.log; exit 1; }
SOURCE=$(sed -n 's/^Built .* from //p' dist/package.log)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
unzip -q dist/cehpoint-soc-agent-submission.zip -d "$TMP"
cd "$TMP/cehpoint-soc-agent"
unset NVIDIA_API_KEY SOC_LLM_PROVIDER SOC_DB_PATH SOC_REPORTS_DIR SOC_RUNS_DIR SOC_HERMES_HOME SOC_DATA_DIR SOC_FAULTS
STEPS=()
run_step() {      # name, command...
  local name=$1; shift
  echo "== $name"
  if "$@" > "$TMP/step.log" 2>&1; then STEPS+=("$name|1|$(tail -1 "$TMP/step.log" | tr -d '|\r' | cut -c1-120)")
  else STEPS+=("$name|0|$(tail -3 "$TMP/step.log" | tr '\n|' ' /' | cut -c1-200)"); tail -20 "$TMP/step.log"; fi
}
run_step "new venv ($BASE_PY)" "$BASE_PY" -m venv .venv
run_step "pip install -r requirements.txt && pip install -e ." bash -c ".venv/bin/pip install -q -r requirements.txt && .venv/bin/pip install -q -e . && .venv/bin/pip list 2>/dev/null | grep -i hermes"
run_step "python scripts/check_secrets.py" .venv/bin/python scripts/check_secrets.py
run_step "python -m soc_agent check" .venv/bin/python -m soc_agent check
run_step "pytest" .venv/bin/python -m pytest -q -p no:cacheprovider
run_step "python scripts/run_scenarios.py (mock)" bash -c ".venv/bin/python scripts/run_scenarios.py 2>&1 | grep -E 'passed;'"
run_step "scripts/demo.sh (no .env: MOCK fallback)" bash -c "PYTHON=.venv/bin/python scripts/demo.sh 2>&1 | grep -E 'Demo complete|MOCK LLM - a deterministic' | tr -d '\033' | sed 's/\[[0-9;]*m//g' | tail -2 | tr '\n' ' '"
run_step "python -m soc_agent verify-audit (demo db)" env SOC_DB_PATH=state/demo.db .venv/bin/python -m soc_agent verify-audit
cd "$ROOT"
"${PYTHON:-$([[ -x .venv/bin/python ]] && echo .venv/bin/python || echo python3)}" - "$SOURCE" "$("$BASE_PY" -c 'import platform; print(platform.python_version())')" "${STEPS[@]}" <<'PYEOF'
import json, sys
from datetime import datetime, timezone
source, py, *steps = sys.argv[1:]
rows = [dict(zip(("step", "ok", "detail"), s.split("|", 2))) for s in steps]
for r in rows:
    r["ok"] = r["ok"] == "1"
    r["detail"] = ("- " + r["detail"].strip()) if r["detail"].strip() else ""
out = {"when": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "source": source, "python": py,
       "steps": rows, "ok": all(r["ok"] for r in rows)}
open("reports/cleanroom.json", "w").write(json.dumps(out, indent=2) + "\n")
print("\n".join(f"{'PASS' if r['ok'] else 'FAIL'}  {r['step']} {r['detail']}" for r in rows))
print("clean-room verification:", "OK" if out["ok"] else "FAILED")
sys.exit(0 if out["ok"] else 1)
PYEOF
