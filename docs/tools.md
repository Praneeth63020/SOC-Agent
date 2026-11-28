# Tools (evidence, assessment and report tools)

The tools the Hermes agent can call to gather evidence. All four are **read-only** (`read` permission), registered in Hermes's toolset `soc`, and run through the single wrapper in [`src/soc_agent/tools/base.py`](../src/soc_agent/tools/base.py). Code: [`src/soc_agent/tools/evidence.py`](../src/soc_agent/tools/evidence.py).

- **No tool queries a real system or makes a network call.** Each tool reads a local file under `data/`: **SYNTHETIC** logs and assets, a **MOCK** intelligence feed and a **MOCK** CVE database. See [`data/logs/README.md`](../data/logs/README.md).
- **Strict schemas:** input and output schemas live in [`schemas/tools/`](../schemas/tools/) (`<tool>.input.json`, `<tool>.output.json`, JSON Schema 2020-12, `additionalProperties: false`).
- **Try any tool directly** through the same wrapper, with no LLM involved:

  ```bash
  python -m soc_agent tool <name> '<json arguments>' [--fault TOOL:KIND] [--timeout S] [--json]
  ```

  Exit code: `0` ok, `2` rejected (bad input), `1` error or timeout. `--json` prints the full audit entry.

| Tool | Purpose | Inputs | Output (main fields) | Data source | Label |
|---|---|---|---|---|---|
| `search_logs` | Wazuh events (login failures and successes, sudo, new accounts) and tshark TCP sessions | `source` (`wazuh` \| `tshark` \| `all`) + at least one of `account`, `host`, `src_ip`, `dst_ip`, `dst_port`, `event_type`, `start`, `end`; `limit` 1-200 (default 50) | `events[]` {time, source, event_type, account, host, src_ip, dst_ip, dst_port, summary, evidence_ref}, `total_matched`, `returned`, `truncated`, `malformed_lines_skipped`, `counts`, `first_time`, `last_time`, `notes`, `data_label` | `data/logs/wazuh_alerts.jsonl`, `data/logs/tshark_sessions.csv` (+ inventory for IP → host names) | SYNTHETIC |
| `lookup_ip` | IP reputation | `ip` (IPv4) | `found`, `classification` (malicious \| suspicious \| benign \| internal \| unknown), score, categories, report count, first/last seen, ASN, country, `evidence_ref`, `source: "MOCK intel feed"`, `live: false` | `data/intel/ip_reputation.json` | MOCK |
| `search_cve` | Known vulnerabilities for a product version | `product`, optional `version` | `matches[]` {cve_id, cvss, severity, summary, affected ranges, evidence_ref}, `total`, `version_compared`, `version_checked`, `notes`, `source: "MOCK CVE database"`, `live: false` | `data/intel/cve_db.json` | MOCK |
| `get_asset_context` | Business context for a host or an account | exactly one of `host` (name or IPv4) or `account` | `found`, `record` (host: role, criticality, owner, OS, services and versions, internet exposure; account: role, privileged, usual locations / IPs), `evidence_ref` | `data/assets/inventory.json` | SYNTHETIC |

The investigation phase adds one internal tool, `submit_evidence_log` (`write_internal`); see [below](#submit_evidence_log-investigation-phase). Day 3's assessment phase adds `correlate_evidence` (`read`, deterministic, no arguments) and `submit_findings` (`write_internal`); see [Day 3 tools](#day-3-correlate_evidence-and-submit_findings).

Every tool reads from the run's **data root** (`RunContext.data_dir`): `data/` by default, or a scenario root such as `data/scenarios/benign/` (`analyze --data-dir`, `SOC_DATA_DIR`, API `?case=`). The file layout under the root is the same.

## What the wrapper guarantees (every tool)

For each call the wrapper:

1. Finds the run by `task_id`.
2. Checks that the tool is enabled for this phase of the run (otherwise `denied`).
3. Validates the arguments against the **full** input schema (otherwise `rejected`, with readable problems).
4. Checks the permission (otherwise `denied`).
5. Runs the handler **with a timeout**.
6. Validates the result against the **output schema**.
7. Records the evidence refs the result returned.
8. Writes an audit entry.

| Status | When | What the model receives |
|---|---|---|
| `ok` | the handler returned a result matching the output schema | the result (zero matches is `ok`, with a note) |
| `rejected` | bad arguments (schema), or the handler refused the request (e.g. `start` after `end`, an unparseable version) | `{"error", "problems": [...], "hint"}`, so the model can fix exactly those problems |
| `denied` | the tool is not enabled for this phase, or needs a permission the run does not have | `{"error"}` |
| `timeout` | the handler did not finish within the timeout (default **5 s**, `SOC_TOOL_TIMEOUT_S`) | `{"error": "... timed out after 5 s. No data was returned: record this step as failed and do not guess its result.", "retryable": true}` |
| `error` | missing or corrupt data file, an exception, or a result that **does not match the output schema** | `{"error": "...", "retryable": false}` (+ `problems` for schema mismatches). The malformed result is withheld, never passed on |

- **Failures never carry data.** A timed-out or failed call returns only the error. Late results from a timed-out handler are discarded.
- **Missing or corrupt files** give a clear message without a local path, e.g. `Data source cve_db.json is unavailable (file not found).` or `Data source tshark_sessions.csv is corrupt (expected the columns ...)`.
- **The model is sent simplified schemas.** Keywords that some OpenAI-compatible backends reject (`pattern`, `format`, `anyOf`, `oneOf`, `if/then`, ...) are stripped from what the model sees. The wrapper always validates against the full schema.
- **Audit entries** (in the run record `tool_calls`) contain: `seq, tool, permission, arguments, status, result, result_summary, result_truncated, evidence_refs, fault_injected, timeout_s, started_at, finished_at, duration_ms`. A result or argument larger than 20,000 characters is stored as `{"_truncated": true, "original_chars": N, "preview": "..."}`. The model still received the full result, and `evidence_refs` still lists every ref.
- **Fault injection** (tests and demos only): `SOC_FAULTS=lookup_ip:timeout,search_cve:error` or `--fault lookup_ip:timeout`. Kinds are `timeout`, `error` and `malformed`. A fault replaces the handler *after* input validation, is recorded as `fault_injected` in the audit entry, and is shown as `FAULT INJECTION ACTIVE` in the CLI, the warnings and the run record.

### Evidence refs

Every record a tool returns carries an `evidence_ref` that points at exactly one place in the data files:

- `wazuh_alerts.jsonl#L57`: physical line 57 of the file
- `tshark_sessions.csv#row12`: data row 12 below the header
- `ip_reputation.json#203.0.113.77`
- `cve_db.json#CVE-2024-6387`
- `inventory.json#hosts/fin-app-01`, `inventory.json#accounts/j.mehta`

Refs are stable: the same query returns the same refs. `soc_agent.tools.evidence.resolve_ref(ref)` returns the raw record a ref points at. The wrapper remembers every ref a `read` tool returned in the run, and `submit_evidence_log` rejects any ref that was not returned (Day 3's findings will be held to the same rule).

---

## `search_logs`

Schemas: [`search_logs.input.json`](../schemas/tools/search_logs.input.json), [`search_logs.output.json`](../schemas/tools/search_logs.output.json).

| Input | Rules |
|---|---|
| `source` (required) | `wazuh` = login outcomes, sudo, account changes; `tshark` = TCP sessions; `all` = both |
| `account`, `host` | `host` is a host name or its IPv4 address. A tshark session matches if either endpoint is that host |
| `src_ip`, `dst_ip`, `dst_port` | IPv4 dotted quad; port 1-65535 |
| `event_type` | `auth_failure`, `auth_success`, `privilege`, `account_change`, `network_session`, `any` (default) |
| `start`, `end` | ISO 8601 **UTC** (`Z` or `+00:00`), inclusive. A real date is required. `start` must not be after `end`. The window is at most **30 days**. An `end` without fractional seconds covers that whole second (`09:42:17Z` includes `09:42:17.512`) |
| `limit` | 1-200, default 50. The **earliest** matching events are returned. `counts` and `total_matched` cover all matches |
| at least one filter | besides `source`: `{"source": "wazuh"}` alone is rejected |

Normalization:
- **Wazuh rule groups → `event_type`:** `authentication_failed` / `invalid_login` → `auth_failure`; `authentication_success` → `auth_success`; `sudo` → `privilege`; `adduser` and similar → `account_change`.
- **Wazuh fields:** `account` is `data.dstuser` (for sudo, the user who ran it: `data.srcuser`); `host` is `agent.name`; `dst_ip` is `agent.ip`.
- **tshark rows:** become `network_session` events. `host` is the inventory name of the destination (or else the source). `account` is always `null`, because SSH is encrypted and tshark never shows login success.
- **Bad lines:** unreadable Wazuh lines (bad JSON, unusable timestamp) and CSV rows are skipped and counted in `malformed_lines_skipped`. The SYNTHETIC header lines are not counted.

Example (valid):

```bash
python -m soc_agent tool search_logs '{"source": "wazuh", "src_ip": "203.0.113.77", "account": "a.rao"}'
```
```json
{
  "query": {"event_type": "any", "limit": 50, "source": "wazuh", "src_ip": "203.0.113.77", "account": "a.rao"},
  "events": [
    {"time": "2026-11-18T09:29:40.204Z", "source": "wazuh", "event_type": "auth_failure", "account": "a.rao",
     "host": "fin-app-01", "src_ip": "203.0.113.77", "dst_ip": "10.20.5.17", "dst_port": null,
     "summary": "Wazuh rule 5760 (level 5) sshd: authentication failed. | Nov 18 09:29:40 fin-app-01 sshd[22850]: Failed password for a.rao from 203.0.113.77 port 50811 ssh2",
     "evidence_ref": "wazuh_alerts.jsonl#L9"},
    "... 2 more ..."
  ],
  "total_matched": 3, "returned": 3, "truncated": false, "malformed_lines_skipped": 2,
  "counts": {"by_event_type": {"auth_failure": 3}, "by_source": {"wazuh": 3}},
  "first_time": "2026-11-18T09:29:40.204Z", "last_time": "2026-11-18T09:30:21.390Z",
  "notes": [], "data_label": "SYNTHETIC"
}
```
`[search_logs] status: OK  |  3.3 ms  |  3 matched, 3 returned; auth_failure 3; 2 malformed line(s) skipped`

Example (rejected; the handler never runs):

```bash
python -m soc_agent tool search_logs '{"source": "wazuh", "limit": 500, "user": "x"}'
```
```json
{"error": "Invalid arguments for search_logs.",
 "problems": ["(root): Additional properties are not allowed ('user' was unexpected)",
              "limit: 500 is greater than the maximum of 200"],
 "hint": "Call the tool again with arguments matching its schema."}
```

## `lookup_ip`

Schemas: [`lookup_ip.input.json`](../schemas/tools/lookup_ip.input.json), [`lookup_ip.output.json`](../schemas/tools/lookup_ip.output.json).

- **Valid input:** an IPv4 address only. IPv6, leading zeros, out-of-range octets, multicast, `0.0.0.0` and broadcast are rejected.
- **Internal addresses:** RFC 1918, loopback and link-local addresses give `classification: "internal"` without consulting the feed. (Python's `ipaddress.is_private` is deliberately **not** used: it also covers the RFC 5737 documentation ranges, which this lab uses as stand-ins for internet addresses.)
- **Unknown addresses:** `found: false, classification: "unknown"` with the note *"Absence of data does not mean the address is benign."*
- **Always labelled:** every result says `source: "MOCK intel feed", live: false, data_label: "MOCK"`.

```bash
python -m soc_agent tool lookup_ip '{"ip": "203.0.113.77"}'
```
```json
{"ip": "203.0.113.77", "found": true, "classification": "malicious", "reputation_score": 92,
 "categories": ["ssh-bruteforce", "password-spraying", "scanner"], "report_count": 148,
 "first_seen": "2026-09-02T11:20:00Z", "last_seen": "2026-11-18T09:45:00Z", "asn": 64500,
 "as_org": "Example Hosting Ltd (MOCK)", "country": "ZZ",
 "source": "MOCK intel feed", "live": false, "data_label": "MOCK", "evidence_ref": "ip_reputation.json#203.0.113.77"}
```

Timeout (fault injection):

```bash
python -m soc_agent tool lookup_ip '{"ip": "203.0.113.77"}' --fault lookup_ip:timeout --timeout 1
```
```json
{"error": "lookup_ip timed out after 1 s. No data was returned: record this step as failed and do not guess its result.", "retryable": true}
```
`[lookup_ip] status: TIMEOUT  |  1006.1 ms  |  ...` (exit code 1)

## `search_cve`

Schemas: [`search_cve.input.json`](../schemas/tools/search_cve.input.json), [`search_cve.output.json`](../schemas/tools/search_cve.output.json).

- **Product names:** `sshd`, `ssh` and `openssh-server` are aliases of `openssh`. Matching is case-insensitive.
- **Versions:** `8.9p1`, `9.6`, or a distribution package version such as `1:8.9p1-3ubuntu0.6`, which is reduced to the upstream `8.9p1`.
- **Version-range aware:** a CVE matches when `introduced <= version < fixed` for any of its ranges. For example `8.9p1` gives 4 CVEs, `8.7p1` gives 5, `9.6p1` gives 1 and `9.8p1` gives none.
- **No version given:** every CVE for the product is listed, with `version_checked: false`.
- **Unknown product or no match:** `matches: []` with a note. This is a valid result.
- **Not modelled:** distribution backports (a note says so on every result for a known product).
- **Always labelled:** `source: "MOCK CVE database", live: false`. The entries are modelled on public OpenSSH advisories but abbreviated. Verify them against NVD before relying on them.

```bash
python -m soc_agent tool search_cve '{"product": "sshd", "version": "1:8.9p1-3ubuntu0.6"}'
```
```json
{"product": "sshd", "product_matched": "openssh", "version": "1:8.9p1-3ubuntu0.6", "version_compared": "8.9p1",
 "version_checked": true,
 "matches": [{"cve_id": "CVE-2024-6387", "cvss": 8.1, "severity": "high", "summary": "Signal handler race condition in sshd (\"regreSSHion\") ...",
              "affected": [{"introduced": "8.5p1", "fixed": "9.8p1"}, {"introduced": "0", "fixed": "4.4p1"}],
              "evidence_ref": "cve_db.json#CVE-2024-6387"}, "... 3 more ..."],
 "total": 4,
 "notes": ["Upstream version ranges only: distribution backports (e.g. Ubuntu security updates) are not considered, so a listed CVE may already be fixed in the installed package."],
 "source": "MOCK CVE database", "live": false, "data_label": "MOCK"}
```

## `get_asset_context`

Schemas: [`get_asset_context.input.json`](../schemas/tools/get_asset_context.input.json), [`get_asset_context.output.json`](../schemas/tools/get_asset_context.output.json).

- **Input:** exactly one of `host` (name or IPv4) or `account`. Giving both or neither is rejected.
- **Not found:** an unknown name gives `found: false` with no `record`.
- **Output schema:** checks the record's shape separately for a host and for an account.

```bash
python -m soc_agent tool get_asset_context '{"account": "j.mehta"}'
```
```json
{"kind": "account", "query": "j.mehta", "found": true,
 "record": {"name": "j.mehta", "display_name": "J. Mehta (fictitious)", "role": "Finance analyst", "department": "Finance",
            "privileged": false, "usual_locations": ["Pune office (on-site)"], "usual_source_ips": ["10.20.1.45"],
            "usual_login_method": "publickey", "hosts": ["fin-app-01"], "notes": "Not expected to use sudo on fin-app-01."},
 "evidence_ref": "inventory.json#accounts/j.mehta", "data_label": "SYNTHETIC"}
```

```bash
python -m soc_agent tool get_asset_context '{"host": "fin-app-01", "account": "j.mehta"}'
```
```json
{"error": "Invalid arguments for get_asset_context.",
 "problems": ["(root): give exactly one of host or account (call the tool twice for both)"],
 "hint": "Call the tool again with arguments matching its schema."}
```

---

## `submit_evidence_log` (investigation phase)

Permission `write_internal`. Code: [`src/soc_agent/tools/investigation.py`](../src/soc_agent/tools/investigation.py). Schema: [`schemas/evidence_log.schema.json`](../schemas/evidence_log.schema.json).

**Arguments** are the evidence log itself, as two top-level arrays:

- `executed_steps[]` = {`step`, `tool`, `reason`, `outcome` (`found` \| `none` \| `failed`), `evidence_refs[]` (≤ 20)}
- `skipped_steps[]` = {`step`, `tool`, `reason`}

There is no field for a severity, verdict or recommendation.

**Accepted only if it is consistent with the run's audit trail:**
- every `evidence_ref` was returned **in this run** by **that step's tool** (otherwise: `evidence_ref 'wazuh_alerts.jsonl#L999' was not returned by any tool in this run`)
- `found` cites at least one ref; `none` and `failed` cite none
- `failed` needs a call of that tool that did not succeed; `found` and `none` need one that did
- every plan step appears exactly once, with the tool the plan names; `analyst_review` steps can only be skipped (they are human-only)

At most 3 attempts are allowed, and only one log can be accepted per run.

**Why the evidence log is passed as top-level arrays:** in the first live NVIDIA run, a nested `{"evidence_log": {...}}` argument was twice sent as a malformed JSON string. Validation is unchanged.

---

## Day 3: `correlate_evidence` and `submit_findings`

Code: [`src/soc_agent/tools/assessment.py`](../src/soc_agent/tools/assessment.py), [`src/soc_agent/correlate.py`](../src/soc_agent/correlate.py), [`src/soc_agent/severity.py`](../src/soc_agent/severity.py). The rubric is described in [`severity.md`](severity.md).

### `correlate_evidence` (read, no arguments)

This tool runs the **deterministic** correlation on the results that the evidence tools returned **in this run**. The wrapper keeps every successful read result in `RunContext.evidence_results`. The correlation reads no file and calls no model. The agent decides *when* to call it, but the code computes the result.

| Output field | Content |
|---|---|
| `timeline` | events related to the alert's account / host / source IP / outbound destinations, sorted, each with a `phase` (`baseline`, `attack`, `compromise`, `post_compromise`, `post_attack`). The model gets a **condensed** view (identical rows merged, with count and first/last refs); the assessment stores every event |
| `facts[]` | `{id, statement, evidence_refs, data}`: `failures_by_account`, `failures_by_src_ip`, `success_after_failures` (same IP? seconds after the last failure), `login_session` (tshark session that carried the login), `source_ip_baseline` (usual IPs + earlier logins), `source_ip_type`, `source_ip_reputation` (MOCK), `other_accounts_targeted`, `host_context`, `account_context`, `post_compromise_privileged`, `post_compromise_account_changes`, `post_compromise_outbound` (with destination reputation), `tshark_vs_wazuh` |
| `gaps[]` | `{id, key_source, statement}`: key sources that failed, timed out, are missing or were not queried; plus a failed `search_cve`, truncated searches, a search window that missed the alert's failures or the 30 minutes after the login |
| `conflicts[]` | `{id, statement, evidence_refs, possible_explanations}`: tshark sessions vs Wazuh attempts, alert counts / times vs the logs |
| `sources` | status per key source: `ok`, `failed`, `missing`, `not_queried`, `partial`, `not_applicable` |
| `suggested_follow_ups[]` | concrete calls that would close coverage gaps, e.g. `search_logs source=wazuh account=j.mehta start=... end=...` |
| `signals` | the machine-readable inputs of the rubric, with the refs behind each |

### `submit_findings` (write_internal)

The arguments **are** the findings ([`schemas/findings.schema.json`](../schemas/findings.schema.json)), as 16 top-level fields: the six answers (`account_and_asset`, `timeline`, `source_ip_intelligence`, `related_events`, `severity_justification`, `containment`), each `[{statement, evidence_refs}]`; then `hypotheses`, `severity`, `severity_rationale`, `severity_evidence_refs`, `confidence`, `confidence_rationale`, `mitre`, `unknowns`, `alternative_explanations` and `recommended_next_steps`.

Checks, in code (at most 5 content-checked submissions, plus a separate budget of 5 submissions rejected for format errors such as a missing field or a string where an object belongs, so format slips do not use up the content attempts; one accepted per run). A resubmission that leaves out a required field gets it from the model's own previous submission in this run, **unless the previous attempt had problems in that field**: then it must be sent again, fixed. The merged findings get the full schema and every check, and the reply names the fields carried over or refused. Every problem names the field to change, e.g. `add "ip_reputation.json#203.0.113.77" to severity_evidence_refs`:

- every `evidence_ref` was returned by a tool **in this run**, and every claim cites at least one; anything without a ref belongs in `unknowns`
- `hypotheses` list exactly the plan's ids; `supported` and `refuted` cite refs
- MITRE ids come from the local catalog [`data/mitre_catalog.json`](../data/mitre_catalog.json), with the exact name, and the cited refs include an event of the kind the technique needs (failed logins for T1110.\*, two or more accounts for T1110.003, a success for T1078, sudo for T1548.003, an account creation for T1136.001, a session for T1071.001 / T1041 / T1048). T1110 / T1110.001 also need at least 10 failed logins in the run (the brute-force threshold). T1078 / T1078.003 / T1133 / T1021.004 need a cited login from outside the account's baseline (a user's own login from their usual IP is not adversary activity). T1021.004 is lateral movement: it also needs a login from an internal source; an internet login with valid credentials is T1078 (T1133 for an internet-facing service)
- a **benign hypothesis that contradicts the deterministic facts** is challenged once: refuted although rule L2 (benign explanation supported) holds, or supported although the rubric says high/critical. The rejection lists the facts. If the model keeps its status and its reasoning addresses them (e.g. mentions the baseline), it is accepted and recorded in `severity_check.hypothesis_challenges`, never overwritten
- if the correlation has gaps, `unknowns` must be non-empty and confidence cannot be `high`; a conflict also rules out `high`
- any text (claim, hypothesis reasoning, severity rationale, MITRE justification) citing `ip_reputation.json#...` must say **MOCK** intel; a statement about the reputation of an IP (with words like reputation / intel, or a verdict such as "203.0.113.77 is malicious" / "a known C2 server") must cite that IP's lookup ref; if `lookup_ip` failed for that IP, it can only go in `unknowns`; a verdict about an IP that was never looked up in this run is refused. Free text without refs (`confidence_rationale`, `alternative_explanations`, next steps) gets the same verdict checks and must say MOCK when it mentions a looked-up IP's reputation
- `unknowns` must contain real entries (placeholders such as "None." are refused)
- refs only become citable when an **evidence tool** returned them (`search_logs`, `lookup_ip`, `search_cve`, `get_asset_context`); `get_alert` and `correlate_evidence` never add citable refs, so a ref planted in an alert cannot be cited
- `containment` next steps need `requires_approval: true` (nothing is executed), and a containment action (block, disable, isolate, reset a password, ...) cannot be labelled `investigative` to avoid that
- severity is compared with the rubric. It may differ by at most one level (a larger deviation is always rejected, with the facts that contradict the claimed level). If it differs by one level, the rationale must mention the rubric and its level (e.g. "the rubric says critical, but …"). The first time it doesn't, the submission is rejected with the rubric's factors; after that it is accepted and recorded. The agent's severity is never overwritten.

The result is `{accepted, message, severity_check: {agent_severity, rubric_severity, agrees, rubric_rule, rubric_score, rationale_addresses_rubric, accepted_after_rubric_hint, agent_confidence, rubric_confidence, confidence_agrees}}`.

## Day 4: `request_action` and `submit_report_content` (report phase)

The report phase's agent gets exactly these two tools, both `write_internal`. `block_ip`, `disable_account` and `isolate_host` (permission `disruptive`) are defined in [`tools/actions.py`](../src/soc_agent/tools/actions.py) only so their permission is explicit. `register_tools` refuses to give them to Hermes, and the wrapper denies them in any run. Security rationale and tests: [`docs/security.md`](security.md).

### `request_action` (write_internal)

Input ([`schemas/tools/request_action.input.json`](../schemas/tools/request_action.input.json)), exactly these fields (`additionalProperties: false`, so `approved`, `analyst`, `status`, … are rejected):

| field | rule |
|---|---|
| `action_type` | `block_ip` \| `disable_account` \| `isolate_host` |
| `target` | an IPv4 address / account / host that appears as an entity field in the alert or in this investigation's evidence; at least one cited ref must name it (unless the alert does); never a protected asset ([`data/assets/protected_assets.json`](../data/assets/protected_assets.json), read from the project only) |
| `reason` | 10–600 characters |
| `evidence_refs` | 1–12 refs returned by tools in this investigation |
| `expected_impact` | 10–400 characters |

The same type + target cannot be requested twice while pending or approved. A run allows at most 6 accepted requests (12 calls). The result is `{accepted: true, action_id: "ACT-XXXXXXXXXX", status: "pending", expires_at, message}`: the action is stored with status `pending` and the investigation moves to **Awaiting Approval**. Nothing is executed. Only an analyst can decide (`soc_agent actions approve|reject`), and execution is simulated (`soc_agent actions execute`).

### `submit_report_content` (write_internal)

Input ([`schemas/tools/submit_report_content.input.json`](../schemas/tools/submit_report_content.input.json)): `executive_summary` (≤ 150 words), `summary_evidence_refs`, `recommendations` `[{priority, action, type investigative|containment|remediation, rationale, expected_impact, evidence_refs, requires_approval, pending_action_id?}]`. Checks:
- every ref was returned in this investigation; IP reputation in the summary cites the lookup_ip ref and says MOCK intel
- containment / remediation need `requires_approval: true`; a containment verb can't be labelled `investigative`
- unique priorities; `pending_action_id` must be an action of this investigation, used once, on a containment recommendation; every action requested in this run must be cited
- 3 attempts; accepted once

The result is `{accepted: true, message}`. The rest of the incident report is assembled by code ([`report.py`](../src/soc_agent/report.py)).

