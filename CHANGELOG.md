# Changelog

Day-by-day summary of the prototype. Commits and dates are taken from `git log` (no dates are invented). Per-day demo scripts: [`docs/history/`](docs/history/README.md).

## Day 5: integration, testing, hardening, documentation (final "Day 5" commit on main)

- **End-to-end flow and first run**: `run` ends with a result block (severity / confidence and rubric agreement, report paths, pending actions, the exact approve / reject / execute / close commands). `scripts/demo.sh`: fresh demo database -> check -> compromise scenario (NVIDIA if a key is set, otherwise MOCK with a loud notice; also falls back to MOCK if the real-model run fails or requests nothing) -> execute without approval (refused) -> approval as "hermes" (refused) -> analyst approval -> SIMULATED execution (twice, idempotent) -> reject the rest -> close -> report -> audit -> verify-audit.
- **`check`** reports Python, hermes-agent, provider / model, key set or missing (never the value), limits, fault injection, database (writable / locked), reports / runs / Hermes home, analyst token, data files, scenarios and the four locked-down toolsets; `check --live` sends one 4-token request to verify key, model and network.
- **Setup errors**: one line plus an actionable hint, no stack trace, for an unsupported Python, missing key, NVIDIA 401/403/404/429/5xx, network down, missing data dir, locked / unwritable / old database (`errors.py`); unexpected crashes are summarized and the traceback goes to `state/errors.log`; API 502 bodies carry the hint. Hermes's own console output goes to the run record (`hermes.console`) instead of the terminal. `SOC_API_MAX_RETRIES` (default 6): Hermes's default of 3 retries ran out against NVIDIA's rate limit.
- **Scenario matrix** for the brief's five categories: new `normal` scenario (one mistyped password, low-level Wazuh alert, then the usual login) and `tool_failure_logs` (search_logs cannot read a damaged Wazuh export); every scenario has a brief category and a containment expectation (`requested` / `none` / `any`). `scripts/run_scenarios.py` now runs the full `run` pipeline (plan -> assess -> report) for every scenario, plus two rejection runs and three safety runs (approval bypass, forged analyst approval, prompt-injection line), in a fresh database whose audit chain is verified; `--provider nvidia --repeat N --pause S` records pass/fail, submissions, validation failures, latency and tokens per phase.
- **Fixes from the final review** (details and tests in [`docs/security.md`](docs/security.md#day-5-review-findings-and-what-was-done)): `execute` requires an approved decision row (a status edited in the database no longer suffices) and `verify-audit` checks every action's state; `phases` and `reports` are hash-chained (older rows accepted as a prefix); every expiry is a chained `action_events` row; fault injection is labelled in `run` output and the report; the report's SYNTHETIC label follows the data actually read; Markdown links / images / emphasis cannot be injected into reports; agent names such as `Hermes2` are refused as analysts. The mock no longer recommends containment when the login outcome is unknown, and falls back to the other log source when one file cannot be read. Actions and investigations created in the same millisecond are listed in creation order (they were tie-broken by their random ids, which made `test_execute_needs_an_approved_decision_not_just_the_status_column` fail about 1 run in 8).
- **Test report and samples**: `scripts/make_test_report.py` -> [`docs/test-report.md`](docs/test-report.md) (pytest junit + coverage, MOCK matrix, NVIDIA matrix, safety tests, flaky check, clean-room result); `scripts/check_flaky.sh`; one generated sample report per scenario in [`docs/samples/`](docs/samples/README.md).
- **Packaging**: `scripts/package_submission.sh` (zip from `git archive`, content check, secret scan of the extracted copy; `--worktree` for verification before committing) and `scripts/verify_clean_room.sh`.
- **CI**: secret scan -> check -> pytest with coverage + junit -> scenario matrix -> verify-audit -> demo -> test report artifact.
- **Docs**: final README, [`docs/hermes-design.md`](docs/hermes-design.md), end-to-end diagrams and "what is sent to the LLM" in [`docs/architecture.md`](docs/architecture.md), updated [`docs/security.md`](docs/security.md), [`docs/assessment-mapping.md`](docs/assessment-mapping.md), [`docs/review-checklist.md`](docs/review-checklist.md), [`docs/demo-script.md`](docs/demo-script.md); per-day documents moved to `docs/history/`. Removed unused helpers (`store.open_store`, `report.generated_stamp`, `tools/assessment._mentions`).

## Day 4: incident report, audit trail, approval workflow (commit `27fc1e7`)

- Report phase (third Hermes conversation) with exactly two tools: `request_action` (a validated, **pending** request for `block_ip` / `disable_account` / `isolate_host`; invented, wrong-kind, protected and duplicate targets rejected) and `submit_report_content` (executive summary + prioritized recommendations, refs checked). The disruptive tools are never registered with Hermes.
- Incident report assembled by code from the stored assessment (JSON validated against `schemas/incident_report.schema.json` + Markdown), versioned after every analyst decision.
- SQLite history and audit trail `state/soc.db`: investigations, phases, tool calls, evidence, reports, pending actions, decisions, simulated actions, status history; append-only triggers, sha256 hash chains, `verify-audit`.
- Analyst path (`approvals.py`, CLI `actions` / `close`, token-protected API): human name and reason required, one decision per action, 24 h expiry, SIMULATED idempotent execution, request digest bound to the decision, close rules.
- Safety scenarios: approval-bypass script, SYNTHETIC prompt-injection log line (`wazuh_alerts.jsonl#L68`), `docs/security.md` threat model.

## Day 3: investigation workflow, severity and confidence (commit `2f6ed89`)

- One Hermes conversation that investigates and assesses (`analyze`): the agent chooses tools from the alert and the results, explains each call, skips and adds steps.
- `correlate_evidence` (deterministic timeline with phases, facts, gaps, conflicts, follow-ups from this run's results only) and `submit_findings` (the six brief questions with evidence refs, hypotheses, separate severity and confidence rationales, MITRE from a local catalog with evidence, unknowns, next steps).
- Deterministic severity / confidence rubric (`severity.py`, `docs/severity.md`), compared with the agent's severity and never overwriting it.
- Six SYNTHETIC scenarios with expected outcomes; real-model runs and the fixes they prompted (documented in `docs/history/`).

## Day 2: evidence tools (commit `a487343`)

- `search_logs`, `lookup_ip`, `search_cve`, `get_asset_context` with input and output schemas, SYNTHETIC Wazuh / tshark logs, MOCK intel and CVE data, SYNTHETIC asset inventory.
- Wrapper: output-schema validation, timeouts, missing / corrupt data handling, fault injection (tests and demos only), evidence refs, audit.
- Investigation phase (`investigate`) with `submit_evidence_log` and tool-call traces.

## Day 1: foundation (committed, 2026-11-20)

`git log` (oldest first):

- `435eeaf` Add project scaffolding, settings and secret scan
- `d1d33d9` Add alert schema, synthetic sample alerts and intake
- `ce002aa` Add locked-down Hermes runtime, tool wrapper and offline mock LLM
- `13aa990` Add planner, CLI and API with end-to-end Hermes tests
- `7fc13d9` Add CI workflow and Day 1 documentation
- `c34e63d` Test that a run never creates the user's ~/.hermes
- `41f4c64` Harden alert intake and plan checks found in review
- `f2cfec4` Raise default output cap to 4096 tokens; config and scanner edge cases
- `298e1e4` Default to nvidia/nemotron-3.5-lightning-30b-a3b
- `da99b49` Make the plan format explicit and give precise feedback on bad plans
