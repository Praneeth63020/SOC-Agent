# Sample incident reports (generated, not edited)

Every file here was written by `python scripts/run_scenarios.py --samples`: version 1 of the incident report of the first run of each scenario, copied unchanged (JSON + Markdown). The investigation and action ids exist only in the database of the run that produced them.

## `mock/`: MOCK LLM (deterministic script, not an AI model), SYNTHETIC data

| Brief category | Scenario | Report | Outcome |
|---|---|---|---|
| normal | `normal` | [`mock/normal.md`](mock/normal.md) / [`.json`](mock/normal.json) | low / high, benign explanation supported, no containment requested |
| suspicious | `compromise` | [`mock/compromise.md`](mock/compromise.md) / [`.json`](mock/compromise.json) | critical / high, four containment requests **pending** an analyst |
| benign | `benign` | [`mock/benign.md`](mock/benign.md) / [`.json`](mock/benign.json) | low / high, benign hypothesis supported, no containment |
| incomplete | `incomplete` | [`mock/incomplete.md`](mock/incomplete.md) / [`.json`](mock/incomplete.json) | high / low, gaps: missing tshark export, host not in the inventory |
| tool failure | `tool_failure` | [`mock/tool_failure.md`](mock/tool_failure.md) / [`.json`](mock/tool_failure.json) | critical / medium, lookup_ip timed out (FAULT INJECTION banner), reputation unknown |
| tool failure | `tool_failure_logs` | [`mock/tool_failure_logs.md`](mock/tool_failure_logs.md) / [`.json`](mock/tool_failure_logs.json) | medium / low, Wazuh file unreadable, no Wazuh evidence cited, no containment |
| additional | `failures_only`, `conflicting` | [`mock/failures_only.md`](mock/failures_only.md), [`mock/conflicting.md`](mock/conflicting.md) | low / high; high / low with the tshark vs Wazuh conflict |

The **[MOCK LLM]** banner and the `[MOCK]` prefix on every agent text mark the mock; the **SYNTHETIC LAB DATA - MOCK INTELLIGENCE** banner marks the data. These reports show the pipeline and the report format, not model reasoning.

## `nvidia/`: real model on NVIDIA NIM

Reports produced by the real model (`nvidia/nemotron-3.5-lightning-30b-a3b`) on 2026-11-21 in the NVIDIA scenario matrix; the file name carries the model and the date, and the report's provenance section names the model. For each scenario the first run that met its expectations was copied. The data is still SYNTHETIC and the intelligence MOCK.

| Brief category | Report |
|---|---|
| suspicious | [`nvidia/compromise-nemotron-3.5-lightning-30b-a3b-2026-11-21.md`](nvidia/compromise-nemotron-3.5-lightning-30b-a3b-2026-11-21.md) (critical / medium, rubric agrees; two containment requests pending) |
| normal | [`nvidia/normal-nemotron-3.5-lightning-30b-a3b-2026-11-21.md`](nvidia/normal-nemotron-3.5-lightning-30b-a3b-2026-11-21.md) |
| benign | [`nvidia/benign-nemotron-3.5-lightning-30b-a3b-2026-11-21.md`](nvidia/benign-nemotron-3.5-lightning-30b-a3b-2026-11-21.md) |
| incomplete | [`nvidia/incomplete-nemotron-3.5-lightning-30b-a3b-2026-11-21.md`](nvidia/incomplete-nemotron-3.5-lightning-30b-a3b-2026-11-21.md) |
| tool failure | [`nvidia/tool_failure-nemotron-3.5-lightning-30b-a3b-2026-11-21.md`](nvidia/tool_failure-nemotron-3.5-lightning-30b-a3b-2026-11-21.md) |

All runs, including the 4 that failed, are in [`../test-report.md`](../test-report.md) and [`../results/scenarios-nvidia.json`](../results/scenarios-nvidia.json).

A report changes version when an analyst decides an action or closes the investigation (`python -m soc_agent report INV-...` shows the latest); the samples are version 1: actions still pending.
