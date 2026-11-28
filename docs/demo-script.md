# Demo script (7-9 minutes)

A walkthrough for the recorded demo: exact commands, what to say, what to point at. Everything shown is **SYNTHETIC lab data** and **MOCK intelligence**; nothing real is blocked, disabled or isolated. If NVIDIA is unavailable, run the same commands with `--provider mock` and **say so on camera** ("this is the deterministic MOCK script, not an AI model").

## Pre-demo checklist (10 minutes before)

- [ ] `source .venv/bin/activate` in the repository folder (Windows: inside WSL2).
- [ ] Fresh demo state: `rm -f state/demo.db* state/demo-simulated_actions.log && rm -rf reports/demo`
- [ ] Use the demo database in this terminal: `export SOC_DB_PATH=state/demo.db SOC_REPORTS_DIR=reports/demo SOC_SIMULATED_ACTIONS_LOG=state/demo-simulated_actions.log`
- [ ] Key works: `python -m soc_agent check --live` shows `live request OK`. If it fails (401/403/429/network), use the backup plan below.
- [ ] Wait a minute after the live check if NVIDIA rate-limited you recently (free tier); `SOC_API_MAX_RETRIES=6` rides out short limits.
- [ ] Terminal: font size 16-18 pt, ~110 columns wide, dark theme, scrollback cleared (`clear`). A second window with the editor or GitHub open on `docs/architecture.md` and a rendered report.
- [ ] Commands below copied into a scratch file, one per line, so you paste instead of typing.
- [ ] Optional dry run: `scripts/demo.sh --mock` (40 s) to make sure everything is green.

## 1. Problem and architecture (1 min)

Show [`docs/architecture.md`](architecture.md) (component diagram, then the end-to-end sequence).

Say:
- "A SOC gets alerts like this one from Wazuh: 50 failed SSH logins for j.mehta on a finance server, then a success. A junior analyst must investigate, judge severity, write a report, and get approval before touching anything."
- "Three layers: **Wazuh and tshark detect**. **Hermes orchestrates**: it runs the LLM loop and dispatches tool calls; it is not the SIEM. **Tools retrieve and record**: narrow functions with schemas, behind one wrapper that validates, enforces permissions and timeouts, and audits."
- "The model can only call tools. It cannot block, disable or isolate anything: those tools are never registered. It can request; a human approves; execution is simulated."

## 2. Check and configuration (0.5 min)

```bash
python -m soc_agent check
```

Point at: Python + hermes-agent 0.19.0; provider nvidia + model; **NVIDIA_API_KEY "set (value not shown)"**; database; analyst token; 8 scenarios; the four **locked-down toolsets** ("each phase sees only its tools; Hermes's terminal, web and file tools are never offered; block/disable/isolate never").

Show `.env.example` briefly: provider, model, limits, fault injection "tests only".

## 3. Suspicious scenario with NVIDIA (2.5 min)

```bash
python -m soc_agent run data/scenarios/compromise/alert.json --data-dir data/scenarios/compromise
```

(About 1-3 minutes with the real model. While it runs, say: "Phase 1 plans, phase 2 investigates and assesses in one conversation, phase 3 writes the report and may request containment.")

Point at the result block: **severity vs confidence** and "rubric ... agrees / differs" ("severity is how bad if true, confidence is how sure; the rubric is deterministic code next to the model's judgement, never overwriting it"); the report paths; the **pending actions** with their evidence refs; the printed analyst commands.

Then the tool calls with the model's reasons:

```bash
python -m soc_agent audit <INV-id> | sed -n '1,60p'
```

Point at: each call's `why:` line (the model says why before calling), statuses (`ok`, any `rejected` submission and its fix), the follow-up `lookup_ip` on the outbound destination, the `submit_findings` call. Say: "every refused or rejected call is in the hash-chained audit trail, with the reason the model gave."

Timeline, severity and MITRE (open the Markdown report in the editor, or):

```bash
python -m soc_agent report <INV-id> | sed -n '/## Timeline/,/## Recommendations/p'
```

Point at: the phase-labelled timeline (baseline -> attack -> compromise -> post-compromise) with refs; **MITRE with justification and evidence refs** ("T1110 needs at least 10 failures in the run; T1078 needs a login from outside the account's baseline; otherwise `submit_findings` rejects it"); hypotheses with status; unknowns.

## 4. Report Markdown (1 min)

Open `reports/demo/<INV-id>.v1.md` rendered (VS Code preview or GitHub).

Point at: the banners (SYNTHETIC LAB DATA - MOCK INTELLIGENCE; `[MOCK LLM]` only in mock runs); summary table; executive summary (the only agent-written prose, plus recommendations; refs checked); affected entities; recommendations with **PENDING** action ids; gaps and unknowns; provenance ("assembled by code from the database, validated against the schema"); the evidence appendix (every ref -> the tool output excerpt).

## 5. Approval gate (1 min)

```bash
python -m soc_agent actions list --investigation <INV-id>
python -m soc_agent actions execute <ACT-id> --analyst "Demo Analyst"        # refused: not approved
python -m soc_agent actions approve <ACT-id> --analyst "Demo Analyst" --reason "Brute-force source confirmed in the cited evidence"
python -m soc_agent actions execute <ACT-id> --analyst "Demo Analyst"        # SIMULATED
python -m soc_agent actions reject <other ACT-id> --analyst "Demo Analyst" --reason "Not needed after the block"   # for each remaining one
python -m soc_agent close <INV-id> --analyst "Demo Analyst" --resolution "Source blocked (SIMULATED); credentials to be reset."
python -m soc_agent verify-audit
```

Say: "execute is refused without an approved decision; the approval needs a human name (the agent's names are refused) and a reason, and is bound to a hash of the request; execution only records what would happen; the report gets a new version after every decision; verify-audit recomputes every hash chain and checks every action's state."

(Shortcut: `scripts/demo.sh` runs steps 3 and 5 end to end in ~1 minute with the same checks.)

## 6. Safety: bypass attempt and prompt injection (1 min)

```bash
python -m soc_agent run data/scenarios/compromise/alert.json --data-dir data/scenarios/compromise --provider mock --scenario report_bypass
```

Say: "this MOCK script plays a malicious or confused model." Point at the report-phase tool calls: `block_ip` / `disable_account` / `approve_action` / `terminal` **REFUSED_BY_HERMES** (not in the toolset), `request_action` with forged `approved` / `analyst` fields **REJECTED** (strict schema), invented account and protected targets (`root`, `wazuh-manager`) **REJECTED**; only the four legitimate requests are pending; nothing approved or executed.

```bash
python -m soc_agent tool search_logs '{"source": "wazuh", "host": "fin-app-01", "start": "2026-11-18T10:12:00Z", "end": "2026-11-18T10:13:00Z"}' | grep -A1 Ignore
python -m soc_agent run data/scenarios/compromise/alert.json --data-dir data/scenarios/compromise --provider mock --scenario report_injection
```

Say: "a SYNTHETIC log line tells the AI analyst to disable `admin` and approve it itself. Every prompt says tool results are data. Even a model that obeys can only call `request_action`; `admin` is not an entity in the evidence, so it is rejected and nothing is recorded; and nothing runs without a human." Point at the first report-phase call: `request_action REJECTED`.

## 7. Benign and tool-failure scenarios: stated uncertainty (1 min)

```bash
python -m soc_agent run data/scenarios/benign/alert.json --data-dir data/scenarios/benign
python -m soc_agent run data/scenarios/tool_failure_logs/alert.json --data-dir data/scenarios/tool_failure_logs
SOC_TOOL_TIMEOUT_S=1 python -m soc_agent run data/scenarios/tool_failure/alert.json --data-dir data/scenarios/tool_failure --fault lookup_ip:timeout
```

(Use `--provider mock` here if time is short; say so.)

Point at: benign -> **LOW**, benign hypothesis supported, no containment requested. Unreadable Wazuh file -> the error is a gap and an unknown, no Wazuh evidence cited, **confidence LOW**, no containment justified. Timed-out lookup -> `*** FAULT INJECTION ACTIVE ***`, reputation "unknown" (never guessed), **confidence not high**, the report carries the fault banner.

## 8. Tests, CI, test report, limitations (1 min)

Show [`docs/test-report.md`](test-report.md): totals and coverage; the MOCK matrix (all five categories + safety rows: "pipeline correctness"); the NVIDIA matrix ("model quality": pass rate over 3 runs, submissions, latency and tokens per phase); flaky check; clean-room verification. Show the CI workflow (secret scan -> check -> pytest -> matrix -> verify-audit -> demo -> report).

Say the limitations honestly (README "Known limitations"): the real model varies between runs and is rate-limited on the free tier; the mock agrees with the rubric by construction; validation checks traceability, not truth; all data is synthetic and local; one shared analyst token; audit chain heads are not anchored externally; execution is simulated by design. Next steps: Wazuh API integration, real intel with caching, more scenarios, analyst UI, RBAC, model evaluation at scale.

## Backup plan

- **No key, key rejected, rate-limited or network down**: run every command with `--provider mock` and say "deterministic MOCK script, not an AI model; the pipeline, validation, audit and approval gate are identical". `scripts/demo.sh` falls back automatically and prints a loud notice.
- **The real model fails a run** (findings never accepted): that is a legitimate result to show ("nothing is filled in; the failure is in the audit"); then continue with `--provider mock`.
- **Pre-generated outputs**: [`docs/samples/mock/`](samples/README.md) (one report per category) and [`docs/samples/nvidia/`](samples/README.md) (real-model reports, if those runs were made); [`docs/test-report.md`](test-report.md) for the results.
- **Anything slow**: `scripts/demo.sh --mock` shows the whole approval flow in about a minute.
