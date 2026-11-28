# Day 5 review checklist

The code was reviewed against the scoring rubric and the brief's constraints (no fabricated evidence, label mock data, no real systems, data minimization, separate severity and confidence, MITRE only with evidence, auditability), once by the author and once by an independent reviewer that ran the mock pipeline against every control. Each item: **pass** (already correct), **fix** (a defect fixed today, with a regression test) or **limitation** (medium / low, documented instead of half-fixed).

## Brief constraints

| # | Item | Result | Where / test |
|---|---|---|---|
| 1 | No fabricated evidence: every claim cites refs returned in this run; failed tools return no data | pass | `tools/assessment.py`, `tools/base.py`; `test_findings.py`, `test_evidence_tools.py::test_injected_timeout_returns_no_data` |
| 2 | Refs only from evidence tools (not from `get_alert` / `correlate_evidence`) | pass | `tools/base.py`; `test_findings.py` |
| 3 | The mock recommended blocking an IP when the login outcome was unknown (auth logs unreadable) | **fix** | `mock_llm.build_mock_findings`; `test_assessment.py::test_unreadable_wazuh_file_is_stated_and_nothing_is_invented` |
| 4 | MOCK LLM labelled everywhere (CLI, `[MOCK]` text, report banner, provenance) | pass | `cli.py`, `mock_llm.py`, `report.py`; `test_report.py::test_markdown_has_every_section_and_the_labels` |
| 5 | SYNTHETIC label taken from the alert's flag instead of the data read | **fix** | `tools/evidence.data_dir_synthetic`, `report.build_report`; `test_day5_hardening.py::test_the_evidence_label_follows_the_data_not_the_alert` |
| 6 | Fault injection not labelled in `run` output / report | **fix** | `cli._run`, `report.py`; `test_day5_hardening.py::test_fault_injection_is_labelled_in_the_run_output_and_the_report` |
| 7 | No real systems: no network tool, execution SIMULATED, disruptive tools never registered | pass | `tools/actions.py`, `tools/base.register_tools`, `approvals.execute`; `test_bypass.py::test_disruptive_tools_are_never_registered_with_hermes` |
| 8 | Data minimization: raw alert payload never sent or stored; no memory / context files | pass | `tools/planning._get_alert`, `store.ensure_investigation`, `hermes_runtime`; `test_plan_and_tools.py::test_get_alert_minimizes_data_and_refuses_other_alerts` |
| 9 | Hermes request dumps in `.hermes/sessions/` hold prompts and tool results (key masked) | limitation | `security.md` residual risks; `.hermes/` git-ignored and excluded from the zip |
| 10 | Severity and confidence separate, each with its own rationale; rubric never overwrites | pass | `schemas/findings.schema.json`, `severity.py`; `test_severity.py`, `test_findings.py` |
| 11 | MITRE only with evidence (catalog + event types + thresholds) | pass | `tools/assessment.py`; `test_findings.py` |
| 12 | Auditability: every phase, call, decision, simulation, status change stored | pass | `store.py`; `test_store.py::test_every_phase_of_a_run_is_in_the_database` |

## Approval gate and audit trail

| # | Item | Result | Where / test |
|---|---|---|---|
| 13 | `execute` trusted the mutable status column (a rejected action edited to "approved" could run; verify-audit said OK) | **fix** | `approvals.execute`, `store._check_action_states`; `test_day5_hardening.py::test_execute_needs_an_approved_decision_not_just_the_status_column` |
| 14 | `phases` / `reports` not chained: an assessment row inserted with SQL changed the report unnoticed | **fix** | `store.py` (`HASHED_TABLES`, `CHAINED_LATER`); `test_a_phase_row_inserted_outside_the_application_breaks_verify_audit`, `test_an_older_database_is_migrated_and_its_unchained_rows_are_accepted_as_a_prefix` |
| 15 | Only the last of several expiries was audited | **fix** | `approvals._mark_expired`, `action_events` table; `test_every_expiry_is_a_chained_action_event` |
| 16 | Evidence rows append-only but not chained; chain heads not anchored outside the DB | limitation | `security.md` residual risks |
| 17 | Pending request committed before its tool-call audit row (written at phase end) | limitation | `security.md` residual risks |
| 18 | Agent names with digits / prefixes accepted as analysts (`Hermes2`, `AgentSmith`) | **fix** | `approvals.check_analyst`; `test_names_of_the_agent_are_refused`, `test_human_names_are_accepted` |
| 19 | Markdown link / image / emphasis injection into the report from agent or log text | **fix** | `report._cell`; `test_report_text_cannot_inject_links_images_or_emphasis` |
| 20 | Bypass attempts (direct tools, forged fields, invented / protected targets, terminal) | pass | `test_bypass.py`; matrix safety rows |
| 21 | Prompt-injection log line | pass | `test_bypass.py::test_followed_injection_creates_nothing_and_executes_nothing`; matrix row |
| 22 | One shared API token; self-declared analyst name | limitation | `security.md` residual risks |
| 23 | `actions execute --analyst` help text was wrong | **fix** | `cli.py` |
| 24 | Failed runs stay "Under Investigation" | limitation | `security.md` residual risks |

## Usability, robustness and code quality

| # | Item | Result | Where / test |
|---|---|---|---|
| 25 | Stack traces / Hermes advice ("run hermes setup") shown for user errors | **fix** | `errors.py`, `cli.main`, `hermes_runtime.build_agent`; `test_a_locked_database_is_explained_without_a_traceback`, `test_an_unexpected_crash_is_summarized_and_logged`, `test_hermes_console_output_goes_to_the_run_record` |
| 26 | NVIDIA 401/403/404/429/5xx and network errors not explained | **fix** | `errors.hint_for` (CLI + API `hint`); `test_known_errors_get_an_actionable_hint`; reproduced live with an invalid key (HTTP 403), an unknown model (404) and an unreachable endpoint |
| 27 | Hermes's 3 retries too few for NVIDIA's free-tier rate limit (every assessment failed with 429) | **fix** | `SOC_API_MAX_RETRIES` (default 6); `test_hermes_api_retries_come_from_the_settings` |
| 27b | Live NVIDIA run (normal scenario): the model left out `containment` when nothing needed containing; 5 format rejections said only "'containment' is a required property" and the run failed | **fix** (feedback, not validation): missing required fields get a field-specific explanation (`ToolSpec.field_hints`), and the assessor prompt says containment is never empty | `tools/base._with_field_hint`, `tools/assessment.SUBMIT_FINDINGS`, `prompts.ASSESSOR_SYSTEM`; `test_a_missing_containment_answer_is_explained_not_waived` |
| 27c | Live NVIDIA run (normal scenario): the findings said "No immediate containment action required", yet the report phase requested `isolate_host fin-app-01` (it would have waited for an analyst, but the report contradicted itself) | **fix** (stricter, not looser): `request_action` is rejected unless the accepted findings recommend that action for that target; the reporter prompt says so | `tools/actions.findings_recommend`, `prompts.REPORTER_SYSTEM`; `test_request_action_must_match_the_accepted_findings` |
| 28 | Unsupported Python crashed inside Hermes imports | **fix** | `__main__.py`, `errors.python_problem`; `test_python_version_check` |
| 29 | `check` lacked key / DB / token / data status | **fix** | `cli._check`; `test_check_reports_state_without_showing_secrets`, `test_check_live_explains_a_rejected_key` |
| 30 | Brief's "normal" scenario and a search_logs failure variant missing | **fix** | `data/scenarios/normal`, `data/scenarios/tool_failure_logs`; `test_assessment.py::test_scenario_end_to_end_meets_its_expectations[normal|tool_failure_logs]` |
| 31 | Mock fell back only when tshark was missing, not when the Wazuh file was unreadable | **fix** | `mock_llm._other_source` |
| 32 | Dead code (`store.open_store`, `report.generated_stamp`, `tools/assessment._mentions`) | **fix** | removed |
| 33 | No TODO / FIXME left; no secrets or raw alert payloads in logs (`errors.log` stores the command name and traceback only) | pass | `grep -rn "TODO\|FIXME" src scripts tests` is empty; `scripts/check_secrets.py` |
| 34 | `docs/tools.md` said 4 format rejections for findings; the code allows 5 | **fix** | `docs/tools.md` |
| 35 | Flaky tests | pass (see the test report's flaky-test check) | `scripts/check_flaky.sh` |
| 36 | Real-model non-determinism (output varies; several submissions needed) | limitation | README known limitations; NVIDIA section of the test report |
| 37 | Validation checks traceability, not truth of each statement | limitation | README known limitations |
