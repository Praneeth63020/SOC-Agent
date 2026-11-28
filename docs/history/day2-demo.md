# Day 2 demo script (about 5 minutes)

**What it shows:** the approved evidence tools (log search, IP reputation, CVE lookup, asset context) with clear input and output schemas, tested on synthetic data. Every call is validated, failures are handled safely, and outputs are predictable. Then Hermes calls the tools for a real investigation, and every call is traced with its reason, status, duration, result and evidence refs.

Before starting: `source .venv/bin/activate`. Steps 1-2 and 4 need no API key. Step 3 uses NVIDIA if `.env` has `NVIDIA_API_KEY`, otherwise `--provider mock`.

---

### 1. Tool calls directly through the wrapper (1.5 min)

No LLM is involved here: `soc_agent tool` runs one tool through **the same wrapper** Hermes uses.

**A valid call:** the spraying signal (a.rao attacked from the same IP).

```bash
python -m soc_agent tool search_logs '{"source": "wazuh", "src_ip": "203.0.113.77", "account": "a.rao"}'
```

Point out:
- The **normalized events**, each with an `evidence_ref` such as `wazuh_alerts.jsonl#L9`. Open `data/logs/wazuh_alerts.jsonl` at line 9: it is that exact line.
- `malformed_lines_skipped: 2`: the two deliberately broken lines were skipped, not crashed on.
- `data_label: "SYNTHETIC"`, and `counts` / `total_matched` / `truncated`.
- The status line: `status: OK | 3.3 ms | 3 matched ...`.

**A rejected call:** bad input never reaches the handler.

```bash
python -m soc_agent tool search_logs '{"source": "wazuh", "limit": 500, "user": "x"}'
python -m soc_agent tool get_asset_context '{"host": "fin-app-01", "account": "j.mehta"}'
```

You get `status: REJECTED` (exit code 2) with readable problems, e.g. `'user' was unexpected`, `limit: 500 is greater than the maximum of 200`, `give exactly one of host or account`.

Optional, 20 s:

```bash
python -m soc_agent tool lookup_ip '{"ip": "203.0.113.77"}'                 # MOCK intel, live: false
python -m soc_agent tool search_cve '{"product": "sshd", "version": "8.9p1"}' # version-range aware, MOCK
```

Say: *"Every result says where it came from: SYNTHETIC lab logs, a MOCK intel feed, a MOCK CVE database. No tool touches a real system or the network."* Show [`schemas/tools/`](../../schemas/tools/) and the table in [`docs/tools.md`](../tools.md).

### 2. A failing tool (30 s)

```bash
python -m soc_agent tool lookup_ip '{"ip": "203.0.113.77"}' --fault lookup_ip:timeout --timeout 1
python -m soc_agent tool search_cve '{"product": "openssh"}' --fault search_cve:malformed
```

- **Timeout:** `status: TIMEOUT` after 1 s, result `{"error": "... No data was returned ...", "retryable": true}`.
- **Malformed output:** the handler returned something that does not match the output schema. You get `status: ERROR` and the malformed result is **withheld**.
- In both cases **no data is returned**, and the fault is labelled `FAULT INJECTED (testing only)`.

### 3. Hermes runs the investigation (2 min; about 2 min with NVIDIA, about 3 s with the mock)

```bash
python -m soc_agent investigate data/alerts/account_compromise.json            # NVIDIA
python -m soc_agent investigate data/alerts/account_compromise.json --provider mock   # offline, labelled MOCK
```

The command runs the Day 1 plan, then the investigation agent. That agent has only `get_alert`, the four evidence tools and `submit_evidence_log` (see `exposed_tools` in the run record).

Walk through the **tool-call trace**:
- Each row shows `#`, tool, status, duration and a one-line result. With the mock that is 6 evidence calls: `search_logs` ×3, `lookup_ip`, `get_asset_context`, `search_cve`.
- **`why:`** is the model's stated reason for the call ("Step 3: Check approved intelligence for 203.0.113.77").
- **`args:`** are the exact arguments. The `search_cve` version (`8.9p1`) came from the `get_asset_context` result.
- **`refs:`** are the evidence refs the call returned.

Then the **evidence log**: per plan step, the tool, the reason, the outcome (`FOUND` / `NONE` / `FAILED`) and the cited refs. `analyst_review` is `SKIPPED` (human-only). Say: *"There is no severity, verdict or recommendation yet. That is Day 3, and only on evidence that is in this log."*

Show that cited evidence must be real:

```bash
python -m soc_agent investigate data/alerts/account_compromise.json --provider mock --scenario investigate_fake_ref
```

The first `submit_evidence_log` is **REJECTED**: `evidence_ref 'wazuh_alerts.jsonl#L999' was not returned by any tool in this run`. The second submission is accepted. *(The real NVIDIA model did exactly this in a live run: it cited `wazuh_alerts.jsonl#L23`, a line it had never been given, and was rejected the same way.)*

### 4. The tool-failure scenario (1 min)

```bash
SOC_TOOL_TIMEOUT_S=2 python -m soc_agent investigate data/alerts/account_compromise.json \
    --provider mock --scenario investigate_tool_failure
```

- The banner shows `*** FAULT INJECTION ACTIVE (testing only): {'lookup_ip': 'timeout'} ***`.
- In the trace, `lookup_ip` is **TIMEOUT** after 2 s and has no refs.
- In the evidence log, `step 3 [lookup_ip] FAILED` with `cited: (none)`. The investigation still completes.
- The warnings say `Evidence is incomplete: plan step(s) [3] failed and returned no data.`

Say: *"The agent was told the tool failed. It got no data, and nothing was invented in its place."*

Finally, the run record and trace:

```bash
python -m soc_agent trace INV-YYYYMMDD-XXXXXXXX        # id printed at the end of the investigate output
```

`runs/<id>.investigation.json` holds the task, the exposed tools, any fault injection, every audit entry (arguments, status, result, summary, refs, timestamps, `duration_ms`), the trace and the evidence log. It is linked to the planning record `runs/<id>.json`. The API equivalents are `POST /alerts/investigate?provider=mock` and `GET /runs/<id>/trace`.

### 5. Tests (15 s)

```bash
pytest
```

All tests run offline (mock only). Day 2 adds tests for: every tool and every rejection class, zero results, stable refs that point at the right line or row, the spraying signal, tshark session counts, version ranges, timeouts, missing and corrupt files, malformed output, audit caps, the four investigation scenarios through real Hermes, evidence-log rules, the CLI and the API.

---

**Review checkpoint answers:**
- *Tools validate input:* strict JSON schemas (`additionalProperties: false`, IPv4 and UTC patterns, enums, ranges, at-least-one-filter, exactly-one-of) are checked before the handler runs. Semantic checks (real date, `start <= end`, 30-day window, parseable version, unicast IP) give `rejected` with readable problems.
- *Tools handle failures:* timeouts (concurrent.futures, default 5 s), missing or corrupt data files, exceptions and malformed output all give `timeout` / `error` with a clear message and no data. Nothing crashes the agent.
- *Predictable outputs:* every `ok` result is validated against its output schema. Zero matches is `ok`. Every record carries a stable, checkable `evidence_ref`, and everything is labelled SYNTHETIC or MOCK with `live: false`.
