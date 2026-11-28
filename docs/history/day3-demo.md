# Day 3 demo script (about 5 minutes)

Everything below runs offline with the **mock LLM** (a deterministic script, **not an AI model**, labelled MOCK) through the real Hermes runtime. All data is **SYNTHETIC**; IP intelligence is a **MOCK** feed (`live: false`). To use the real model, replace `--provider mock` with `--provider nvidia`, which needs `NVIDIA_API_KEY`. Real-model runs take 2–5 minutes each, and their output varies (see the README's Known limitations).

Setup, once: `source .venv/bin/activate`.

### 1. Analyze the main alert (1.5 min)

```bash
python -m soc_agent analyze data/alerts/account_compromise.json --provider mock
```

Point out, top to bottom:

- **Plan first.** The Day 1 plan is accepted (7 steps, 3 hypotheses).
- **SEVERITY: CRITICAL (rubric: CRITICAL, rule C1 - agrees).** The agent's severity and the deterministic rubric are shown side by side. The rationale names the factors: 50 failures, success from 203.0.113.77 outside j.mehta's baseline, sudo, new user, high-criticality host.
- **CONFIDENCE: HIGH.** A separate question from severity: every key source (Wazuh, tshark, IP intel, host, account) answered and nothing conflicts.
- **Tool-call trace at the bottom.** Every call has a "why". Plan step 6 (`search_cve`) is **skipped with a reason** (password login, not an exploit). There are two **follow-ups** the plan did not have: j.mehta's usual source IPs, and `lookup_ip 198.51.100.23` after the post-login search showed the server connecting there.

### 2. Walk the timeline and the refs (1 min)

In the **Timeline** table:

| Phase | What to show |
|---|---|
| `baseline` | j.mehta's normal publickey logins from the office IP 10.20.1.45 on 11-16 and 11-17 (`wazuh_alerts.jsonl#L2 .. L3`) |
| `attack` | 3 failures for **a.rao** (spraying), then 50 for j.mehta, plus 53 tshark sessions from the same IP |
| `compromise` | the accepted password login `#L64` and the TCP session that carried it (`tshark_sessions.csv#row61`, 1588 s) |
| `post_compromise` | sudo `#L65`, `useradd backup_svc` `#L66`, 48 MB to 198.51.100.23 `row62` |

Then show that each answer under **Answers** cites refs, and resolve one of them:

```bash
python -c "from soc_agent.tools.evidence import resolve_ref; print(resolve_ref('wazuh_alerts.jsonl#L66'))"
```

The run record holds everything: `runs/<id>.assessment.json` (`assessment.timeline`, `facts`, `rubric`, `severity_check`).

### 3. The benign scenario: low severity (1 min)

```bash
python -m soc_agent analyze data/scenarios/benign/alert.json --data-dir data/scenarios/benign --provider mock
```

- Same code, different SYNTHETIC data root: j.mehta mistyped 4 times from the office IP, then logged in.
- **SEVERITY: LOW (rule L2: benign explanation supported).** The source is in the baseline (inventory and earlier logins), there were few failures, and nothing suspicious followed.
- **H3 SUPPORTED** (the benign hypothesis), and no attack MITRE techniques.
- Notice there is no `lookup_ip` call. The source is internal, and the agent says so instead of querying intel.
- In the timeline, the tshark check shows **5 attempts in 2 SSH sessions: consistent**, because one connection carries several password prompts.

### 4. A failing tool: uncertainty stated (1 min)

```bash
SOC_TOOL_TIMEOUT_S=1 python -m soc_agent analyze data/scenarios/tool_failure/alert.json --data-dir data/scenarios/tool_failure \
    --provider mock --scenario analyze_tool_failure
```

- The banner reads `FAULT INJECTION ACTIVE (testing only)`. In the trace, `lookup_ip` shows `TIMEOUT` three times: the first try, one retry, then the follow-up lookup.
- **SEVERITY: CRITICAL** still, because it rests on the logs, not on intel. **CONFIDENCE: MEDIUM**, with the rubric reason "IP intelligence ... timed out".
- **Unknowns:** "Reputation of 203.0.113.77 is unknown: lookup_ip failed in this run". No claim cites intel (there is none to cite).
- The guard behind this:

```bash
SOC_TOOL_TIMEOUT_S=1 python -m soc_agent analyze data/scenarios/tool_failure/alert.json --data-dir data/scenarios/tool_failure \
    --provider mock --scenario analyze_overconfident
```

  In the trace, the first `submit_findings` is **REJECTED** ("confidence: cannot be high while evidence is missing, failed, timed out ...", "unknowns: must not be empty"). The second is accepted. The same happens with `--scenario analyze_fake_ref` on the main alert ("evidence_ref 'wazuh_alerts.jsonl#L999' was not returned by any tool in this run").

### 5. All scenarios (30 s)

```bash
python scripts/run_scenarios.py
```

The script prints (and writes to [`day3-scenarios.md`](day3-scenarios.md)) the table *scenario | expected | actual severity / confidence | rubric agrees | submissions | gaps / conflicts | pass* for compromise, benign, failures_only, incomplete, tool_failure and conflicting, plus the two rejection runs: **8 of 8 pass**.

Close with the tests: `pytest -q` (offline, never calls NVIDIA), and [`severity.md`](../severity.md) for the rubric thresholds.
