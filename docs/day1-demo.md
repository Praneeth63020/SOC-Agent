# Day 1 demo script (about 5 minutes)

**What it shows:** the SOC workflow is understood (Hermes vs. SIEM), the project runs reproducibly, the input and output schemas are clear, and an alert becomes a validated, structured investigation plan through the Hermes runtime.

Before starting: `source .venv/bin/activate`, and `.env` contains `NVIDIA_API_KEY` (see README → Setup).

---

### 1. Architecture (1 min)

Open [`docs/architecture.md`](architecture.md) (renders on GitHub).

- **Component diagram:** Wazuh / tshark **detect** and raise the alert. Hermes **decides** which approved tool to call. Tools **retrieve or record**, each call validated, permission-checked and audited. The analyst **approves** any disruptive action.
- One line to say: *"Hermes is the orchestration layer, not the SIEM. It never sees raw logs directly, and it can only call the tools in our `soc` toolset."*
- Point at the **security-model table**: each control is listed with the test that proves it.
- Mention: SSH is encrypted, so tshark shows connection volume and timing but not whether a login succeeded. That outcome comes from Wazuh / `auth.log`.

### 2. Environment (30 s)

```bash
python -m soc_agent check
```

Shows `hermes-agent 0.19.0`, Python, provider `nvidia`, model `nvidia/nemotron-3.5-lightning-30b-a3b`, key `set (not shown)`, and **"hermes agent built OK; tools exposed to the model: get_alert, submit_investigation_plan"**. The locked-down agent is built offline as a smoke test.

### 3. Alert schema and intake (1 min)

```bash
python -m soc_agent validate-alert data/alerts/wazuh_account_compromise.json
```

A raw Wazuh alert (rule 40112, level 12) becomes the normalized shape: level 12 → `severity_hint: high`, `dstuser` → `account: j.mehta`, `srcip` → `src_ip`, MITRE ids kept as hints, `synthetic: true`. Show [`schemas/alert.schema.json`](../schemas/alert.schema.json) briefly.

```bash
python -m soc_agent validate-alert data/alerts/invalid/bad_alert.json
```

The alert is **rejected** (exit code 2) and every problem is listed: unknown key `priority`, invalid IP `203.0.113.777`, timestamp not in UTC.

### 4. Alert → investigation plan with NVIDIA (1.5 min; the call itself takes about 20-70 s)

```bash
python -m soc_agent plan data/alerts/account_compromise.json
```

Walk through the output:
- **Hypotheses**, including at least one marked `[benign]` (user mistyped the password / stale script).
- **Key questions**: the brief's six (account and asset, timeline, IP intelligence, events before and after, justified severity and unknowns, containment for a human).
- **Planned steps**: each names an approved tool (`search_logs`, `lookup_ip`, …) with parameters taken **only from the alert**, plus a rationale and the expected evidence. Containment appears only as an `analyst_review` step.
- **Safety notes, data gaps, warnings.** Any rejected attempt (e.g. an invented indicator the tool refused) shows up here.

*(If the network or key is unavailable: run the same command with `--provider mock`, and say clearly that the mock is a deterministic script, not an AI model. The output is labelled MOCK.)*

### 5. Run record (30 s)

Open the file printed at the end, `runs/INV-YYYYMMDD-XXXXXXXX.json`:
- `task`: the exact system prompt and user message sent.
- `exposed_tools`: `["get_alert", "submit_investigation_plan"]`.
- `tool_calls`: seq, tool, permission, arguments, status, result, timestamps and duration for every call.
- `refused_tool_calls`, `hermes` (API calls, tokens), `warnings`, `status`, `plan`.

### 6. Safety: escape attempt (30 s)

```bash
python -m soc_agent plan data/alerts/account_compromise.json --provider mock --scenario escape
```

The scripted model first tries Hermes's built-in **`terminal`** tool (`touch …`). Hermes refuses it ("Tool 'terminal' does not exist"), the run record lists it under `refused_tool_calls`, no command runs, and the plan still completes. Say: *"This is enforced by the toolset configuration, not by asking the model nicely."*

### 7. Tests (30 s)

```bash
pytest
```

All tests are green and offline. They include the end-to-end runs through the real Hermes runtime: normal, invalid plan then fixed, malformed arguments, escape, no plan (→ failed, nothing invented), and LLM outage (→ failed). The HTTP-500 test takes about 8 s because Hermes retries.

---

**Review checkpoint answers:**
- *Hermes vs. SIEM:* the SIEM detects; Hermes orchestrates tool calls for the investigation.
- *Reproducible:* pinned `requirements.txt`, `python -m soc_agent check`, offline tests, and CI on Python 3.11.
- *Schemas:* `schemas/alert.schema.json` (input) and `schemas/investigation_plan.schema.json` (output), both strict (`additionalProperties: false`).
