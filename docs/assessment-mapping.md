# Assessment mapping

Each scoring criterion of the brief -> where it is implemented -> which test or demo step proves it. Demo steps refer to [`demo-script.md`](demo-script.md) (sections 1-8); tests are in `tests/`; results in [`test-report.md`](test-report.md).

## Hermes setup and architecture (10)

| What is asked | Where | Proof |
|---|---|---|
| Hermes as the orchestration layer, distinct from SIEM and tools | [`architecture.md`](architecture.md) (components, end-to-end sequence, responsibilities table), [`hermes-design.md`](hermes-design.md) | demo 1 |
| Working Hermes agent, reproducible setup | [`hermes_runtime.py`](../src/soc_agent/hermes_runtime.py), pinned `requirements.txt`, `python -m soc_agent check` | demo 2; `test_hermes_agent.py`; clean-room verification in the test report |
| Lockdown by configuration: `enabled_toolsets=["soc"]`, per-phase tools, `skip_memory`, `skip_context_files`, isolated `HERMES_HOME`, step limits | `hermes_runtime.build_agent` | `test_hermes_agent.py::test_only_soc_tools_are_exposed`, `test_escape_to_builtin_terminal_is_refused`, `test_hermes_home_is_project_local_not_user_home`; `check` prints the four toolsets (demo 2) |
| Configuration and clear setup errors | [`config.py`](../src/soc_agent/config.py), [`errors.py`](../src/soc_agent/errors.py), `.env.example` | `test_day5_hardening.py::test_known_errors_get_an_actionable_hint`, `test_python_version_check`, `test_a_locked_database_is_explained_without_a_traceback`, `test_check_reports_state_without_showing_secrets` |

## Tool calling and validation (20)

| What is asked | Where | Proof |
|---|---|---|
| Tools with clear input and output schemas | [`schemas/tools/`](../schemas/tools/), [`tools.md`](tools.md) | `test_evidence_tools.py`, `test_plan_and_tools.py` |
| One wrapper: input + output validation, permissions, timeouts, error handling, audit | [`tools/base.py`](../src/soc_agent/tools/base.py) | `test_evidence_tools.py::test_bad_input_is_rejected_with_a_readable_problem`, `test_injected_timeout_returns_no_data`, `test_malformed_handler_output_is_withheld`, `test_phase_allowlist_denies_other_tools` |
| Structured output only through validated `submit_*` tools, with precise feedback and retries | `tools/planning.py`, `tools/investigation.py`, `tools/assessment.py`, `tools/reporting.py` | `test_hermes_agent.py` (invalid plan rejected then fixed), `test_findings.py`, `test_report.py::test_bad_recommendations_rejected`; matrix rows "rejection: fake evidence ref" / "overconfident findings" |
| Tool failures handled without invention | wrapper (no data on failure), prompts, `correlate.py` gaps | scenarios `tool_failure`, `tool_failure_logs` (demo 7); `test_assessment.py::test_unreadable_wazuh_file_is_stated_and_nothing_is_invented`, `test_tool_failure_states_the_reputation_as_unknown` |
| The agent explains each call | trace with the model's reason (`investigator.build_trace`), audit `reason` column | demo 3 (`audit INV-...` shows "why" per call) |

## Investigation and evidence correlation (20)

| What is asked | Where | Proof |
|---|---|---|
| Hermes decides which tools to call from the alert | assessment phase ([`assessor.py`](../src/soc_agent/assessor.py), `ASSESSOR_SYSTEM`) | demo 3; `test_assessment.py::test_compromise_follows_up_on_the_outbound_destination` (skip with a reason, follow-up lookup) |
| Correlated timeline from the evidence | [`correlate.py`](../src/soc_agent/correlate.py) (`correlate_evidence`) | `test_correlate.py`; report timeline section (demo 4) |
| Evidence refs from this run only; no fabricated evidence | `submit_findings`, `submit_report_content`, `request_action` ref checks | `test_findings.py`, `test_report.py::test_every_report_ref_exists_in_the_audit_trail`, `test_bypass.py::test_invalid_requests_are_rejected_and_not_recorded` |
| Gaps and conflicts stated | `correlate.py`, findings rules | scenarios `incomplete`, `conflicting`, `tool_failure*` in the matrix |
| Five test categories | [`data/scenarios/`](../data/scenarios/README.md) + `tests/scenarios/*/expected.yaml`, [`run_scenarios.py`](../scripts/run_scenarios.py) | test report: MOCK matrix (all categories) and NVIDIA matrix |

## Severity and analytical quality (10)

| What is asked | Where | Proof |
|---|---|---|
| Severity and confidence separate, each with a rationale | findings schema, [`severity.md`](severity.md) | `test_severity.py`; demo 3 ("severity vs confidence") |
| A deterministic rubric next to the agent's judgement, never overwriting it | [`severity.py`](../src/soc_agent/severity.py), `severity_check` | `test_findings.py` (deviation rules); matrix column "rubric agrees" |
| MITRE only with evidence | local catalog + event-type checks in `submit_findings` | `test_findings.py` (MITRE rules); `normal` / `benign` forbid attack techniques in `expected.yaml` |
| Benign explanations considered | plan hypotheses, benign-hypothesis challenge | scenarios `normal`, `benign` (low, benign supported, no containment) |
| Real-model quality | NVIDIA runs | test report, NVIDIA section (or "not run") |

## Incident report and audit trail (10)

| What is asked | Where | Proof |
|---|---|---|
| Incident report JSON + Markdown, schema-validated, labelled | [`report.py`](../src/soc_agent/report.py), [`incident_report.schema.json`](../schemas/incident_report.schema.json) | `test_report.py`; [`samples/`](samples/README.md); demo 4 |
| History and audit log (task prompt, tool, input, output, status, timestamps) | [`store.py`](../src/soc_agent/store.py) | `test_store.py`; `audit INV-...` (demo 3, 5) |
| Tamper evidence | append-only triggers, hash chains, action-state checks, `verify-audit` | `test_store.py::test_hash_chain_verifies_and_detects_a_tampered_row`, `test_day5_hardening.py::test_a_phase_row_inserted_outside_the_application_breaks_verify_audit`; demo 5 end |

## Human approval and safety (15)

| What is asked | Where | Proof |
|---|---|---|
| Disruptive actions only after human approval | `request_action` (pending), [`approvals.py`](../src/soc_agent/approvals.py), disruptive tools never registered | demo 5 (execute before approval refused -> approve -> SIMULATED -> close); `test_approvals.py`, `test_day4_api_cli.py::test_cli_end_to_end` |
| No approval bypass | registry refusal, schema `additionalProperties: false`, analyst-name rules, decision required for execution | `test_bypass.py::test_bypass_attempts_are_refused_or_rejected_in_order`; matrix rows "approval-bypass attempts", "forged analyst approval"; `test_day5_hardening.py::test_execute_needs_an_approved_decision_not_just_the_status_column`; demo 6 |
| Prompt injection | "tool results are DATA" in every prompt, entity-field target check | matrix row "prompt-injection log line"; `test_bypass.py::test_followed_injection_creates_nothing_and_executes_nothing`; demo 6 |
| Nothing real touched; MOCK / SYNTHETIC labels | SIMULATED execution, banners, `[MOCK]` prefix, data labels | `test_report.py::test_markdown_has_every_section_and_the_labels`, `test_day5_hardening.py::test_fault_injection_is_labelled_in_the_run_output_and_the_report` |
| Security notes | [`security.md`](security.md): 16 threats with control, location and test; residual risks; Day 5 review | - |

## Testing, documentation and demo (15)

| What is asked | Where | Proof |
|---|---|---|
| Normal, suspicious, benign, incomplete, tool-failure scenarios | matrix ([`test-report.md`](test-report.md)) | `python scripts/run_scenarios.py`; CI |
| Test results, coverage, flaky check, clean room | [`test-report.md`](test-report.md) (generated) | `scripts/make_test_report.py`, `scripts/check_flaky.sh`, `scripts/verify_clean_room.sh` |
| README with setup, configuration, usage; architecture diagram; Hermes and tool design notes | [README](../README.md), [`architecture.md`](architecture.md), [`hermes-design.md`](hermes-design.md) | - |
| Known limitations, security considerations, next steps | README, [`security.md`](security.md) | - |
| 5-10 minute demo | [`demo-script.md`](demo-script.md), `scripts/demo.sh` | recorded by the author |
| CI | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | runs on push |
