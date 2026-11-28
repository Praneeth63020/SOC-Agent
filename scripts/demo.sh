#!/usr/bin/env bash
# End-to-end demo of the prototype (SYNTHETIC data; nothing real is ever blocked, disabled or isolated).
#
#   scripts/demo.sh            # provider from .env (NVIDIA if a key is set), falls back to MOCK with a loud notice
#   scripts/demo.sh --mock     # offline: real Hermes runtime, scripted MOCK LLM (not an AI model)
#   DEMO_PAUSE=1 scripts/demo.sh   # wait for Enter between steps (for recording)
#
# Steps: fresh demo database -> check -> run the compromise scenario (alert -> plan -> investigate + assess ->
# report) -> show pending actions -> try to execute one WITHOUT approval (must fail) -> approve as an analyst ->
# SIMULATED execution (twice: idempotent) -> reject the rest -> close -> audit trail -> verify-audit.
# Idempotent: it only uses state/demo.db, reports/demo/ and state/demo-simulated_actions.log, which it resets.
#
# Windows: run it inside WSL2 (Ubuntu) from the repository folder; Hermes does not run natively on Windows.
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-}"
if [[ -z "$PY" ]]; then
  if [[ -x .venv/bin/python ]]; then PY=.venv/bin/python; else PY=python3; fi
fi
export SOC_DB_PATH=state/demo.db SOC_REPORTS_DIR=reports/demo SOC_SIMULATED_ACTIONS_LOG=state/demo-simulated_actions.log
SCEN=data/scenarios/compromise
ANALYST="Demo Analyst"

step() { printf '\n\033[1;36m==== %s\033[0m\n' "$*"; if [[ "${DEMO_PAUSE:-}" == 1 ]]; then read -r -p "(Enter) " _; fi; }
loud() { printf '\n\033[1;33m!!!! %s\033[0m\n' "$*"; }
cmd()  { printf '\033[2m$ python -m soc_agent'; printf ' %q' "$@"; printf '\033[0m\n'; "$PY" -m soc_agent "$@"; }

# ---------------------------------------------------------------- provider
PROVIDER=mock
if [[ "${1:-}" != "--mock" ]]; then
  PROVIDER=$("$PY" - <<'EOF'
import os, sys
sys.path.insert(0, "src")
from soc_agent.config import _load_env
_load_env()
p = (os.environ.get("SOC_LLM_PROVIDER") or "nvidia").strip().lower()
print("nvidia" if p == "nvidia" and os.environ.get("NVIDIA_API_KEY", "").strip() else "mock" if p == "nvidia" else p)
EOF
)
  if [[ "$PROVIDER" == mock ]]; then
    loud "No NVIDIA_API_KEY (or SOC_LLM_PROVIDER=mock): this demo uses the MOCK LLM - a deterministic script, NOT an AI model."
  fi
fi

step "0. Fresh demo database (state/demo.db) and reports (reports/demo/)"
rm -f state/demo.db state/demo.db-wal state/demo.db-shm state/demo-simulated_actions.log
rm -rf reports/demo
echo "reset done"

step "1. Environment and configuration"
cmd check || { loud "check found a problem (see above)"; exit 1; }

step "2. Run the suspicious scenario end to end with provider: $PROVIDER"
if ! cmd run "$SCEN/alert.json" --data-dir "$SCEN" --provider "$PROVIDER"; then
  if [[ "$PROVIDER" == nvidia ]]; then
    loud "The NVIDIA run did not complete (real-model output varies; see the audit above). Re-running with the MOCK LLM (NOT an AI model) so the approval demo can continue."
    PROVIDER=mock
    cmd run "$SCEN/alert.json" --data-dir "$SCEN" --provider mock
  else
    exit 1
  fi
fi
INV=$("$PY" -m soc_agent history --json --limit 1 | "$PY" -c "import json,sys; print(json.load(sys.stdin)[0]['id'])")

pending() { "$PY" -m soc_agent actions list --investigation "$INV" --json |
            "$PY" -c "import json,sys; print(' '.join(a['id'] for a in json.load(sys.stdin) if a['status'] == 'pending'))"; }
PENDING=$(pending)
if [[ -z "$PENDING" && "$PROVIDER" == nvidia ]]; then
  loud "The model requested no containment in this run. Re-running with the MOCK LLM (NOT an AI model) to show the approval gate."
  PROVIDER=mock
  cmd run "$SCEN/alert.json" --data-dir "$SCEN" --provider mock
  INV=$("$PY" -m soc_agent history --json --limit 1 | "$PY" -c "import json,sys; print(json.load(sys.stdin)[0]['id'])")
  PENDING=$(pending)
fi
[[ -n "$PENDING" ]] || { loud "no pending action to demonstrate"; exit 1; }
ACT=${PENDING%% *}

step "3. Pending actions: the agent could only REQUEST them"
cmd actions list --investigation "$INV"

step "4. Execute $ACT WITHOUT an analyst approval: must be refused"
if "$PY" -m soc_agent actions execute "$ACT" --analyst "$ANALYST"; then
  loud "UNEXPECTED: executed without approval"; exit 1
fi
echo "-> refused, as required"

step "5. The agent's name is not an analyst: approval as 'hermes' is refused"
if "$PY" -m soc_agent actions approve "$ACT" --analyst hermes --reason "self-approval attempt"; then
  loud "UNEXPECTED: approved by the agent's name"; exit 1
fi
echo "-> refused, as required"

step "6. Analyst approves $ACT, then executes it (SIMULATED; run twice: idempotent)"
cmd actions approve "$ACT" --analyst "$ANALYST" --reason "Demo: brute-force source confirmed in the cited evidence"
cmd actions execute "$ACT" --analyst "$ANALYST"
cmd actions execute "$ACT" --analyst "$ANALYST"

step "7. Reject the remaining requests, then close the investigation"
for A in $(pending); do
  cmd actions reject "$A" --analyst "$ANALYST" --reason "Demo: not needed after the simulated containment"
done
cmd close "$INV" --analyst "$ANALYST" --resolution "Demo: brute-force source blocked (SIMULATED); credentials to be reset."

step "8. Final report (latest version) and audit trail"
cmd report "$INV" | sed -n '1,30p'
echo "..."
cmd audit "$INV" | tail -15

step "9. Verify the hash-chained audit trail"
cmd verify-audit

printf '\n\033[1;32mDemo complete\033[0m (provider: %s%s). Report: reports/demo/  |  database: state/demo.db\n' \
  "$PROVIDER" "$([[ "$PROVIDER" == mock ]] && echo ' - MOCK LLM, not an AI model' || true)"
