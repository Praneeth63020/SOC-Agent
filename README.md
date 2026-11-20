# cehpoint-soc-agent: a Hermes-powered AI SOC analyst (prototype)

A junior-SOC-analyst agent for the Cehpoint AI Engineering Intern assessment. It receives a security alert and plans an investigation using **approved tools only**. Later days add evidence gathering, a report and response actions that a human must approve. Orchestration runs on the **Hermes agent runtime** (Nous Research `hermes-agent` 0.19.0) with an **NVIDIA-hosted LLM** (OpenAI-compatible NIM API, `meta/llama-3.3-70b-instruct`).

Hermes is the orchestration layer only: it decides which approved tool to call. It is **not** the SIEM, log collector or detection engine. Wazuh and tshark-based detections produce the alerts.

> **Status: Day 1 of 5 (foundation).** Architecture, reproducible setup, alert schema and sample alert, and a working Hermes entry point that turns an alert into a validated investigation plan. Evidence tools (Day 2), the investigation workflow (Day 3), reports, audit and approval (Day 4) and final testing (Day 5) are **not** built yet.
>
> All data in this repository is **synthetic lab data**: documentation IP ranges (RFC 5737), invented accounts and hosts.

## Day 1 brief → where it is

| Day 1 brief item | File(s) |
|---|---|
| 1. Document the proposed architecture (incl. Hermes vs. SIEM) | [`docs/architecture.md`](docs/architecture.md): component diagram, sequence diagram, responsibilities table, security-model table |
| 2. Dev environment + minimal Hermes agent | [Setup](#setup) below, [`requirements.txt`](requirements.txt), [`pyproject.toml`](pyproject.toml), [`src/soc_agent/hermes_runtime.py`](src/soc_agent/hermes_runtime.py); `python -m soc_agent check` builds the locked-down agent |
| 3. Small alert schema (JSON) + one sample alert | [`schemas/alert.schema.json`](schemas/alert.schema.json); [`data/alerts/wazuh_account_compromise.json`](data/alerts/wazuh_account_compromise.json) (Wazuh format) and [`data/alerts/account_compromise.json`](data/alerts/account_compromise.json) (normalized); intake in [`src/soc_agent/alerts.py`](src/soc_agent/alerts.py) |
| 4. Agent interaction: alert in → structured investigation plan out | [`src/soc_agent/planner.py`](src/soc_agent/planner.py), [`schemas/investigation_plan.schema.json`](schemas/investigation_plan.schema.json), tools in [`src/soc_agent/tools/`](src/soc_agent/tools/), prompt in [`src/soc_agent/prompts.py`](src/soc_agent/prompts.py) |
| Submission: architecture diagram | [`docs/architecture.md`](docs/architecture.md) (Mermaid, renders on GitHub) |
| Submission: setup instructions | [Setup](#setup) |
| Submission: sample alert JSON | [`data/alerts/`](data/alerts/) (plus a deliberately invalid one in [`data/alerts/invalid/`](data/alerts/invalid/)) |
| Submission: working agent entry point | `python -m soc_agent plan …` ([`cli.py`](src/soc_agent/cli.py)) and `POST /alerts/plan` ([`api.py`](src/soc_agent/api.py)) |
| Submission: short demo script | [`docs/day1-demo.md`](docs/day1-demo.md) |

The scenario is the brief's mandatory one. Account `j.mehta` on host `fin-app-01` (10.20.5.17) has 50 failed SSH logins from `203.0.113.77` between 09:31:02 and 09:41:55 UTC on 2026-11-18. An accepted password login from the same IP follows at 09:42:17 UTC (Wazuh rule 40112, level 12, MITRE hints T1110 / T1078).

## Setup

Requirements: **Python 3.11–3.13** on **Linux or macOS** (Hermes does not run natively on Windows; use **WSL2**). An NVIDIA API key from [build.nvidia.com](https://build.nvidia.com) is needed for real model runs; it is not needed for tests or the offline mock.

```bash
git clone <repo-url> cehpoint-soc-agent && cd cehpoint-soc-agent
python3.11 -m venv .venv && source .venv/bin/activate      # any of 3.11 / 3.12 / 3.13
pip install -r requirements.txt                              # exact, verified versions
pip install -e .
cp .env.example .env                                         # then set NVIDIA_API_KEY in .env
python -m soc_agent check
```

If your system Python is not 3.11–3.13 (e.g. 3.14), install one first, e.g. `uv python install 3.11` and use `$(uv python find 3.11) -m venv .venv`, or use `pyenv` / Homebrew `python@3.11`.

`check` prints the versions, the provider and model (the key is shown only as "set"), and the limits. It then **builds the locked-down Hermes agent offline** and lists the tools it exposes. Expected: `get_alert, submit_investigation_plan`.

### Configuration (`.env`, see [`.env.example`](.env.example))

| Variable | Default | Meaning |
|---|---|---|
| `SOC_LLM_PROVIDER` | `nvidia` | `nvidia` = NVIDIA NIM (real model). `mock` = offline deterministic script, **not an AI model** (tests, CI, demo without a key) |
| `NVIDIA_API_KEY` | (empty) | `nvapi-…`; only in `.env` (git-ignored). Missing → clear error suggesting `--provider mock` |
| `NVIDIA_BASE_URL` | `https://integrate.api.nvidia.com/v1` | OpenAI-compatible endpoint |
| `NVIDIA_MODEL` | `meta/llama-3.3-70b-instruct` | must support tool calling |
| `SOC_MAX_ITERATIONS` | `6` | step limit: Hermes tool-calling rounds per task |
| `SOC_MAX_TOKENS` | `4096` | max output tokens per LLM call |
| `SOC_RUNS_DIR` | `runs` | where run records are written (git-ignored) |
| `SOC_HERMES_HOME` | `.hermes` | Hermes's state folder; project-local so `~/.hermes` is never touched (git-ignored) |

## Run

```bash
# Validate / normalize an alert (raw Wazuh or normalized JSON)
python -m soc_agent validate-alert data/alerts/wazuh_account_compromise.json
python -m soc_agent validate-alert data/alerts/invalid/bad_alert.json        # rejected, exit code 2

# Alert -> investigation plan with the real model (needs NVIDIA_API_KEY)
python -m soc_agent plan data/alerts/account_compromise.json
python -m soc_agent plan data/alerts/account_compromise.json --json --out plan.json

# Same pipeline offline: real Hermes, scripted mock LLM (output labelled MOCK)
python -m soc_agent plan data/alerts/account_compromise.json --provider mock
python -m soc_agent plan data/alerts/account_compromise.json --provider mock --scenario escape
#   scenarios: normal | invalid_first | escape | bad_args | no_submit | http_error

# HTTP API -> http://127.0.0.1:8000/docs
python -m soc_agent serve
curl -s -X POST "http://127.0.0.1:8000/alerts/plan?provider=mock" \
     -H "Content-Type: application/json" -d @data/alerts/wazuh_account_compromise.json
curl -s http://127.0.0.1:8000/runs/INV-YYYYMMDD-XXXXXXXX

# Tests (offline; never call NVIDIA) and secret scan
pytest
python scripts/check_secrets.py
```

Exit codes for `plan`: `0` planned, `1` failed (no valid plan), `2` bad alert or configuration.

API: `GET /health`, `POST /alerts/validate` (422 with the problems if invalid), `POST /alerts/plan?provider=nvidia|mock` (502 if the agent fails, 503 if not configured), `GET /runs/{investigation_id}` (strict id format, no path traversal).

## Input and output

**Input:** a JSON alert. It is either already normalized ([`schemas/alert.schema.json`](schemas/alert.schema.json)) or a raw Wazuh alert, which is normalized automatically: `rule.level` → `severity_hint` (≥13 critical, ≥10 high, ≥6 medium, else low), `data.dstuser` → account, `data.srcip` → `src_ip`, `agent.name` → host, MITRE ids kept as hints. Bad JSON, missing fields, invalid IPs, non-UTC timestamps and unknown keys are rejected with readable errors.

**Output:** the agent's plan content (validated against [`schemas/investigation_plan.schema.json`](schemas/investigation_plan.schema.json)) wrapped with ids and provenance. Abbreviated example:

```json
{
  "plan_id": "PLAN-INV-20261120-2B0F3CB2",
  "investigation_id": "INV-20261120-2B0F3CB2",
  "alert_id": "ALERT-2026-0001",
  "created_at": "2026-11-20T11:52:03.120+00:00",
  "generated_by": {"runtime": "hermes-agent", "provider": "nvidia", "model": "meta/llama-3.3-70b-instruct", "mock": false},
  "synthetic_data": true,
  "summary": "…",
  "hypotheses": [
    {"id": "H1", "description": "…brute-forced…", "benign": false, "would_be_supported_by": "…", "would_be_refuted_by": "…"},
    {"id": "H3", "description": "…the real user mistyped…", "benign": true, "would_be_supported_by": "…", "would_be_refuted_by": "…"}
  ],
  "key_questions": ["Which account and asset are involved…", "…"],
  "steps": [
    {"step": 1, "objective": "…", "tool": "search_logs",
     "parameters": {"account": "j.mehta", "host": "fin-app-01", "event_type": "authentication"},
     "rationale": "…", "expected_evidence": "…"},
    {"step": 3, "objective": "…", "tool": "lookup_ip", "parameters": {"ip": "203.0.113.77"}, "rationale": "…", "expected_evidence": "…"}
  ],
  "safety_notes": ["Disabling j.mehta, blocking 203.0.113.77 or isolating fin-app-01 requires explicit analyst approval."],
  "data_gaps": ["…"]
}
```

The `plan` command returns `{investigation_id, alert_id, status: planned|failed, plan, error, warnings, run_record, duration_ms}`. Every run writes a **run record** `runs/<investigation_id>.json`. It holds the task (system prompt + user message), the tools Hermes exposed, every tool call (arguments, status, result, timestamps, duration), any tool calls Hermes refused, Hermes stats (API calls, tokens, final response), warnings and the outcome.

## How Hermes is used

- **Tools:** `get_alert` (read) and `submit_investigation_plan` (write_internal) are registered in Hermes's tool registry (`tools.registry.registry.register`) under one toolset, `soc`.
- **Agent:** `run_agent.AIAgent(provider="custom", base_url=NVIDIA or mock, enabled_toolsets=["soc"], max_iterations=6, skip_memory=True, skip_context_files=True, …)`. With `enabled_toolsets=["soc"]` Hermes sends the model **only** our two tools. Its built-in terminal, file, browser, web and skills tools are never offered. If a model calls one anyway, Hermes answers "Tool 'terminal' does not exist" and nothing runs.
- **Per-run state:** Hermes calls our handlers with `task_id` = the investigation id. The single tool wrapper uses it to find the run, validates arguments, checks the permission and writes the audit entry.
- **Structured output via a tool:** the plan counts only if the model submits it through `submit_investigation_plan` and the tool accepts it. Invalid plans go back to the model with the exact problems (max 3 attempts). If none is accepted, the result is `failed`; the application never fills in a plan.
- **Isolation:** `HERMES_HOME` points to the project-local `.hermes/` *before* Hermes is imported, so the user's `~/.hermes` config, keys and sessions are never read or modified.
- **Prompting:** Hermes prepends its own identity prompt; our system prompt ([`prompts.py`](src/soc_agent/prompts.py)) is added after it.
- **Mock:** the mock provider is an in-process OpenAI-compatible server on `127.0.0.1` (SSE streaming like a real endpoint). It drives the **real** Hermes loop with a fixed script, which keeps tests and CI offline and reproducible. Its output is labelled `[MOCK]`, `generated_by.mock = true`, plus a warning.

Details, diagrams and the security model with the test that proves each control: [`docs/architecture.md`](docs/architecture.md).

## Project layout

```
├── schemas/                  alert.schema.json, investigation_plan.schema.json
├── data/alerts/              synthetic sample alerts: Wazuh format + normalized (+ invalid/ example)
├── data/logs/                Day 2 evidence (README describes the planned Wazuh + tshark files)
├── src/soc_agent/
│   ├── config.py             settings from .env (nvidia | mock), clear config errors
│   ├── schemas.py            JSON-schema loading + readable validation errors
│   ├── alerts.py             intake: Wazuh -> normalized, validation
│   ├── tools/base.py         ToolSpec, permissions, the single wrapper (validate, permission, audit)
│   ├── tools/planning.py     get_alert, submit_investigation_plan, "no invented indicators"
│   ├── hermes_runtime.py     locked-down Hermes AIAgent, exposed-tool report
│   ├── prompts.py            system prompt + task message
│   ├── planner.py            alert -> plan workflow, run record
│   ├── mock_llm.py           offline OpenAI-compatible mock (scripted, labelled MOCK)
│   ├── cli.py, api.py        entry points (python -m soc_agent …, FastAPI)
├── tests/                    112 offline tests, incl. end to end through real Hermes
├── docs/                     architecture.md, day1-demo.md
├── scripts/check_secrets.py  secret scan (+ .env tracked / ignored checks)
└── .github/workflows/ci.yml  Python 3.11, mock provider: secret scan -> pytest -> mock demo
```

## Known limitations (Day 1)

- **No evidence yet.** The plan only *names* `search_logs`, `lookup_ip`, `search_cve` and `get_asset_context`; they are implemented on Day 2. Nothing is investigated, concluded or contained today.
- **The mock is not AI.** It proves the pipeline (Hermes loop, tool dispatch, validation, audit, refusals), not reasoning quality. Real plans need `NVIDIA_API_KEY`. Real-model output varies between runs and may need the retry path; the CLI shows rejected attempts as warnings.
- **The indicator check is narrow.** It covers IPv4 addresses anywhere in step parameters and values under account/host-like keys. Domains, IPv6 and indicators in free text (e.g. a hypothesis) are not checked yet.
- **Plan quality is not scored.** The schema checks structure, not whether the six questions are answered well; that's a reviewer's job for now.
- **Run records are JSON files.** The SQLite audit trail and the human approval workflow for disruptive actions come on Day 4. Today the permission check only *denies* disruptive tools.
- Hermes adds its own general identity prompt (~8 KB) before ours; it cannot be removed through the public API.
- Each LLM call has a 4096-token output cap (`SOC_MAX_TOKENS`); a very long plan from the real model could be cut off and rejected.
- Linux / macOS / WSL2 only, Python 3.11–3.13.
