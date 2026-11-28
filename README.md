# cehpoint-soc-agent: a Hermes-powered AI SOC analyst (prototype)

A junior-SOC-analyst agent for the Cehpoint AI Engineering Intern assessment. It takes a security alert (Wazuh), plans an investigation, gathers evidence with **approved, read-only tools**, correlates it into a timeline, assesses **severity and confidence separately** with reasoning that cites the evidence, writes an **incident report**, and may only **request** containment: a human analyst approves or rejects it, and execution is **SIMULATED**. Every step is stored in an append-only, hash-chained **audit trail**. Orchestration runs on the **Hermes agent runtime** (Nous Research `hermes-agent` 0.19.0) with an **NVIDIA-hosted LLM** (`nvidia/nemotron-3.5-lightning-30b-a3b`), or offline with a deterministic **MOCK** script that is clearly labelled as not being an AI model. Hermes is the orchestration layer only: Wazuh / tshark detect, the agent investigates, the analyst decides.

> All data is **SYNTHETIC lab data** (RFC 5737 / RFC 1918 addresses, invented accounts and hosts) or a **MOCK** intelligence feed / CVE database. No tool touches a real system or the network; nothing real is ever blocked, disabled or isolated.

## 60-second quickstart

Python **3.11-3.13** on Linux or macOS (Windows: use **WSL2**; Hermes does not run natively on Windows).

```bash
git clone <repo-url> cehpoint-soc-agent && cd cehpoint-soc-agent
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install -e .
cp .env.example .env            # optional: set NVIDIA_API_KEY=nvapi-... for the real model
python -m soc_agent check       # Python, Hermes, provider, key set/missing, DB, data, locked-down toolsets
scripts/demo.sh                 # alert -> report -> approval gate -> SIMULATED execution -> close -> verify-audit
```

Without a key everything works offline with the MOCK LLM (`--provider mock`, or `scripts/demo.sh --mock`); `demo.sh` falls back to it with a loud notice. `python -m soc_agent check --live` sends one 4-token request to verify the key and model.

One alert to a report:

```bash
python -m soc_agent run data/scenarios/compromise/alert.json --data-dir data/scenarios/compromise [--provider nvidia|mock]
```

It ends with the severity / confidence (and whether the rubric agrees), the Markdown + JSON report paths, the pending actions and the exact `approve` / `reject` / `execute` / `close` commands.

## Configuration (`.env`, see [`.env.example`](.env.example))

| Variable | Default | Meaning |
|---|---|---|
| `SOC_LLM_PROVIDER` | `nvidia` | `nvidia` (real model) or `mock` (offline deterministic script, **not an AI model**); `--provider` overrides |
| `NVIDIA_API_KEY` | (empty) | `nvapi-...`, only in `.env` (git-ignored); never printed (`check` shows "set") |
| `NVIDIA_BASE_URL` / `NVIDIA_MODEL` | `https://integrate.api.nvidia.com/v1` / `nvidia/nemotron-3.5-lightning-30b-a3b` | any NIM model with tool calling. The brief named `meta/llama-3.3-70b-instruct`; NVIDIA no longer lists it (checked 2026-11-20) |
| `SOC_MAX_ITERATIONS`, `SOC_INVESTIGATION_MAX_ITERATIONS`, `SOC_ASSESSMENT_MAX_ITERATIONS`, `SOC_REPORT_MAX_ITERATIONS` | 9 / 20 / 28 / 16 | Hermes step limits per phase |
| `SOC_MAX_TOKENS` / `SOC_ASSESSMENT_MAX_TOKENS` | 4096 / 8192 | output tokens per LLM call (assessment and report phases use the larger cap) |
| `SOC_API_MAX_RETRIES` | 6 | Hermes retries per LLM call on HTTP 429 / 5xx (backoff up to 60 s; Hermes's default 3 is too short for NVIDIA's free tier) |
| `SOC_TOOL_TIMEOUT_S` | 5 | per tool call; a slower call returns `timeout` and no data |
| `SOC_FAULTS` | (empty) | **tests / demos only**, e.g. `lookup_ip:timeout`; always labelled FAULT INJECTION in output and reports |
| `SOC_DATA_DIR` | `data` | evidence data root; `--data-dir data/scenarios/<name>` per run |
| `SOC_DB_PATH`, `SOC_REPORTS_DIR`, `SOC_RUNS_DIR`, `SOC_HERMES_HOME` | `state/soc.db`, `reports`, `runs`, `.hermes` | local state, all git-ignored; Hermes never touches `~/.hermes` |
| `SOC_SIMULATED_ACTIONS_LOG` | `data/simulated_actions.log` | where SIMULATED executions are logged |
| `ANALYST_API_TOKEN` | (empty) | header `X-Analyst-Token` for the API's approve / reject / execute / close; empty = those endpoints answer 503 |

## Usage

```bash
# the full flow (plan -> investigate + assess -> report); the agent can only REQUEST actions
python -m soc_agent run data/alerts/account_compromise.json                       # NVIDIA (key in .env)
python -m soc_agent run data/scenarios/benign/alert.json --data-dir data/scenarios/benign --provider mock
python -m soc_agent run data/alerts/account_compromise.json --provider mock --fault lookup_ip:timeout

# analyst path (never reachable by the agent); execution is SIMULATED
python -m soc_agent actions list [--investigation INV-...]
python -m soc_agent actions approve ACT-... --analyst "Your Name" --reason "..."
python -m soc_agent actions reject  ACT-... --analyst "Your Name" --reason "..."
python -m soc_agent actions execute ACT-... --analyst "Your Name"   # refused unless approved
python -m soc_agent close INV-... --analyst "Your Name" --resolution "..."

# reports and audit
python -m soc_agent report INV-... [--format md|json]   # latest version (updated after each decision)
python -m soc_agent history | audit INV-... [--full] | export INV-... | verify-audit

# single phases and single tools (Days 1-3), same wrapper
python -m soc_agent plan|investigate|analyze <alert.json> [--provider mock]
python -m soc_agent tool search_logs '{"source": "wazuh", "account": "j.mehta", "limit": 5}'

# HTTP API (FastAPI, docs at http://127.0.0.1:8000/docs)
python -m soc_agent serve
curl -s -X POST "http://127.0.0.1:8000/alerts/run?provider=mock" -H "Content-Type: application/json" \
     -d @data/alerts/account_compromise.json
curl -s "http://127.0.0.1:8000/investigations/INV-.../report?format=md"
curl -s -X POST http://127.0.0.1:8000/actions/ACT-.../approve -H "X-Analyst-Token: $ANALYST_API_TOKEN" \
     -H "Content-Type: application/json" -d '{"analyst": "Your Name", "reason": "..."}'
```

API: `GET /health`, `POST /alerts/validate`, `POST /alerts/run|plan|investigate|analyze` (`?provider=nvidia|mock`; `run` and `analyze` also `&case=<scenario folder>`), `GET /runs/{id}[/trace|/assessment]`, `GET /investigations[/{id}[/report|/audit]]`, `GET /actions`, analyst-only `POST /actions/{id}/approve|reject|execute` and `POST /investigations/{id}/close` (token, `secrets.compare_digest`; 401 / 409 / 503). A failed phase answers 502 with the error and an actionable `hint`. Exit codes: 0 ok, 1 failed run or refused analyst action, 2 bad input or configuration.

## How it works

**Architecture** ([`docs/architecture.md`](docs/architecture.md): component and sequence diagrams, responsibilities, exactly what is sent to the LLM):

```
SIEM (Wazuh / tshark) --alert--> soc_agent intake --> Hermes AIAgent (toolset "soc", narrowed per phase) <--> LLM
                                       |                         | tool calls
                                       |                         v
                                       |            one tool wrapper: schema in/out, permission, timeout, audit
                                       |                         |  read: SYNTHETIC logs / assets, MOCK intel
                                       v                         v
                     SQLite audit trail (append-only, hash-chained)  <-- report.py (code) --> incident report
                                       ^
                       analyst CLI / API (approvals.py): approve | reject | execute (SIMULATED) | close
```

**How Hermes is used** ([`docs/hermes-design.md`](docs/hermes-design.md)): `AIAgent(provider="custom", enabled_toolsets=["soc"], skip_memory=True, skip_context_files=True, max_iterations=...)` with `HERMES_HOME` set to the project-local `.hermes/`. Each phase's agent offers and dispatches only its own tools; Hermes's built-ins are never offered. Every tool goes through **one wrapper** (input and output JSON-schema validation, per-phase allowlist, permission, timeout, audit). Structured output exists only through validated **`submit_*` tools**; rejected submissions go back to the model with the exact problems. The disruptive tools (`block_ip`, `disable_account`, `isolate_host`) are **never registered** with Hermes.

**Investigation flow** (`run`): (1) *plan*: hypotheses, questions, steps with indicators from the alert only. (2) *investigate + assess* in one conversation: the agent picks tools, says why, skips steps with a reason and follows leads (e.g. an outbound destination); `correlate_evidence` builds a deterministic timeline, facts, gaps and conflicts from this run's results; `submit_findings` answers the brief's six questions with evidence refs and is rejected if any ref was not returned in this run, MITRE is not justified by the cited events, gaps are hidden or confidence is overstated. (3) *report*: the agent may `request_action` (pending) and writes the executive summary and recommendations; everything else in the report is assembled by code and schema-validated ([sample](docs/samples/mock/compromise.md)).

**Severity vs confidence** ([`docs/severity.md`](docs/severity.md)): severity = how bad if true (ordered rules: critical, high, low (benign), medium; e.g. success after brute force plus sudo / new account on a high-criticality host is critical); confidence = how sure (high only if every key source answered, nothing timed out and nothing conflicts). A deterministic rubric is computed next to the agent's judgement and recorded as `agrees` / `differs`; the agent's severity is **never overwritten**, and a disagreement must be argued.

**Approval workflow**: `request_action` (target must be an entity named by the alert or this investigation's evidence, cited by a ref; protected SOC assets refused) -> **pending** (status *Awaiting Approval*) -> analyst approve / reject (a human name, a reason, one decision, 24 h expiry) -> `execute` only if an approved decision exists -> **SIMULATED** effect recorded -> analyst `close`. The agent has no path to `approvals.py`.

**Audit trail**: `state/soc.db` stores every phase (task prompts, exposed tools, Hermes stats), every tool call in order (arguments, status, result, the model's reason, timestamps), evidence excerpts, report versions, requests, decisions, simulations and status changes. Triggers make the tables append-only; sha256 hash chains cover phases, reports, tool calls, decisions, simulations, status changes and expiry events; `verify-audit` recomputes them and checks every action's state against its decisions.

## Test results

Full report (generated from the recorded results): [`docs/test-report.md`](docs/test-report.md).

| Check | Result |
|---|---|
| pytest (offline; never calls NVIDIA) | **619 passed, 0 failed**; line coverage **94 %** of `src/soc_agent` |
| flaky-test check | 3 more full runs: 619 / 619 passed each time; no test changed outcome |
| scenario matrix, MOCK LLM (pipeline correctness) | **13 of 13**: normal, suspicious, benign, incomplete, two tool-failure variants, two extra Day 3 cases, two rejection runs, three safety runs (approval bypass, forged approval, prompt injection) |
| scenario matrix, NVIDIA `nemotron-3.5-lightning-30b-a3b` (model quality), 3 runs per category | **11 of 15**: normal 3/3, incomplete 3/3, benign 2/3, tool failure 2/3, suspicious 1/3. In every completed run the agent's severity agreed with the rubric. Failures: three runs used up their findings attempts (MOCK-intel labels, a MITRE name repeated wrong, refs to correlation fact ids), one compromise run did not cite the sudo / useradd lines. p50 latency: plan 38 s, assess 325 s, report 54 s |
| clean-room verification (zip -> empty folder -> new venv -> install -> secret scan, check, pytest, matrix, demo, verify-audit) | **all steps pass** |
| CI on GitHub | not run from here (runs on push) |

Run them yourself: `pytest` (offline; never calls NVIDIA), `python scripts/run_scenarios.py` (scenario matrix; `--provider nvidia --repeat 3` for the real model), `scripts/check_flaky.sh`, `python scripts/make_test_report.py`, `scripts/verify_clean_room.sh`. CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)): secret scan -> check -> pytest with coverage + junit -> scenario matrix (mock) -> verify-audit -> demo -> test report artifact.

Sample incident reports (generated, unedited): one per category from the MOCK LLM, and the real model's reports, e.g. the suspicious scenario: [`docs/samples/nvidia/compromise-nemotron-3.5-lightning-30b-a3b-2026-11-21.md`](docs/samples/nvidia/compromise-nemotron-3.5-lightning-30b-a3b-2026-11-21.md). Index: [`docs/samples/`](docs/samples/README.md).

## Security considerations

Summary of [`docs/security.md`](docs/security.md) (threat model: 16 threats, each with its control, where it is enforced and the test that proves it; Day 5 review findings; residual risks):
- **Least privilege by configuration, not by prompt**: toolset lockdown, per-phase tools, disruptive tools never registered, analyst path unreachable from the tool layer.
- **No fabricated evidence**: every claim cites refs returned in this run; failed tools return no data; the report is assembled by code.
- **Prompt injection**: tool results are data; a fooled model can at most create a validated *pending* request (the SYNTHETIC injection line in the compromise logs is rejected).
- **Secrets**: only in `.env` (git-ignored), never printed or stored; secret scanner in CI; the submission zip comes from `git archive`.
- **Data minimization**: the raw alert payload is never sent to the LLM or stored; only synthetic / approved lab data may be sent.

## Known limitations

- **The real model is not deterministic.** 11 of 15 NVIDIA runs met their expectations; runs needed 2-11 findings submissions, and 3 used up their attempts (a run whose findings are never accepted is `failed`; nothing is filled in). The model sometimes repeats the same rejected mistake (e.g. a MITRE name) until the attempts run out. The free NVIDIA tier rate-limits (HTTP 429); an assessment takes ~5 minutes. See the NVIDIA section of the test report.
- **The MOCK LLM agrees with the rubric by construction**: the mock rows prove the pipeline, not reasoning quality.
- **Validation checks traceability, not truth**: a claim must cite real refs of this run, but the code does not check that the cited event says what the claim says (except MITRE event types, IP reputation and the analytical checks listed in `docs/tools.md`).
- **All evidence is local and SYNTHETIC / MOCK**; no live Wazuh, packet capture, intel feed or CVE service. Correlation is scoped to the alert's account / host / source IP (no multi-host campaigns).
- **Rubric thresholds are a documented design choice** (brute force >= 10 failures, 30-minute post-login window), not a standard.
- **Audit tamper evidence, not tamper proof**: chain heads are not anchored outside the database; evidence rows are not chained (see residual risks).
- **One shared analyst token** and a self-declared analyst name; no per-user identity or roles.
- **Execution is a simulation** by design: there are no firewall / directory / EDR connectors.
- Hermes adds its own ~8 KB identity prompt; Linux / macOS / WSL2 and Python 3.11-3.13 only.

## Next steps

- Real SIEM integration: pull alerts from the Wazuh API (and push status back), replacing the file-based intake.
- Real threat intelligence and CVE APIs (e.g. AbuseIPDB, NVD) behind the same tool schemas, with caching, rate limits and client-side timeouts.
- More detection scenarios (lateral movement, malware, web attacks) and multi-host correlation.
- An analyst UI (queue, report view, one-click approve/reject) on top of the existing API.
- RBAC and per-analyst identity (SSO/OIDC), a two-person rule for high-impact actions, real connectors with dry-run mode.
- Anchor the audit chain heads in a write-once store; chain the evidence table.
- Model evaluation at scale: more scenarios x more runs per model, tracked over time, to choose and tune the model.

## Project layout

```
├── src/soc_agent/            cli.py, api.py (entry points); config.py, errors.py (settings, setup hints)
│   ├── alerts.py             intake: Wazuh -> normalized alert, validation
│   ├── hermes_runtime.py     locked-down Hermes AIAgent per phase
│   ├── prompts.py            system prompts + task messages (plan, investigate, assess, report)
│   ├── planner.py, investigator.py, assessor.py, reporter.py   the phases; reporter.run_alert = `run`
│   ├── correlate.py, severity.py   deterministic timeline / facts / gaps and the rubric
│   ├── report.py, store.py, approvals.py   incident report, audit trail, analyst path
│   ├── scenarios.py, mock_llm.py   test scenarios + expected outcomes; offline MOCK LLM (labelled)
│   └── tools/                base.py (the wrapper), planning, evidence, investigation, assessment, actions, reporting
├── schemas/                  alert, plan, evidence log, findings, assessment, incident report; tools/<tool>.{input,output}.json
├── data/                     alerts/, logs/, intel/ (MOCK), assets/, scenarios/<name>/ (SYNTHETIC), mitre_catalog.json
├── tests/                    offline pytest suite; scenarios/<name>/expected.yaml
├── scripts/                  demo.sh, run_scenarios.py, make_test_report.py, check_flaky.sh, verify_clean_room.sh,
│                             package_submission.sh, check_secrets.py, make_synthetic_logs.py
├── docs/                     architecture, hermes-design, tools, severity, security, assessment-mapping, review-checklist,
│                             demo-script, test-report, samples/, results/ (NVIDIA raw results), history/ (Days 1-4)
└── .github/workflows/ci.yml
```

## Progress and assessment mapping

Day-by-day summary: [`CHANGELOG.md`](CHANGELOG.md) (per-day demo scripts in [`docs/history/`](docs/history/README.md)). Scoring criterion -> implementation -> test / demo step: [`docs/assessment-mapping.md`](docs/assessment-mapping.md). Code review checklist against the brief's constraints: [`docs/review-checklist.md`](docs/review-checklist.md). Demo walkthrough: [`docs/demo-script.md`](docs/demo-script.md).
