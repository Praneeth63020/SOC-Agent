# Severity and confidence rubric

The rubric is **deterministic code** ([`src/soc_agent/severity.py`](../src/soc_agent/severity.py)). It reads the facts that [`correlate.py`](../src/soc_agent/correlate.py) computed from **this run's tool results only**. No LLM is involved.

The agent states its **own** severity and confidence in `submit_findings`. The code compares them with the rubric:

- **Severity.** A different severity is **never overwritten**, but the agent's discretion is bounded: it may differ from the rubric by **at most one level**. A larger deviation is rejected every time, with the conditions the claimed level needs and the facts of the run that contradict them (e.g. "high and critical need a successful login after the failures; in this run no successful login was found"). Within one level, the agent's `severity_rationale` must address the difference: it must mention the rubric and its level, and cite evidence. If it doesn't, the first such submission is rejected, with the rubric's factors as a hint. After that the submission is accepted, and the disagreement is recorded in the assessment as `severity_check: {agent_severity, rubric_severity, agrees, rationale_addresses_rubric, accepted_after_rubric_hint}`.
- **Confidence.** The agent's confidence can never be `high` when the correlation found a gap or a conflict, and `unknowns` must then be non-empty. Agreement with the rubric's confidence is recorded too.

Severity and confidence are **separate questions**:

| | Question | Example |
|---|---|---|
| **Severity** | How bad is it *if the evidence is right*? | sudo + new account after a brute-forced login on a finance server: critical |
| **Confidence** | How complete and consistent is the evidence? | lookup_ip timed out, so the source IP's reputation is unknown: medium |

A critical alert can have low confidence (incomplete evidence), and a low-severity alert can have high confidence.

## Inputs (signals from the correlation)

| Signal | From | Notes |
|---|---|---|
| success after failures | Wazuh `auth_success` for the alert's account **on the alert's host** after its first `auth_failure` **in the alert's window** (15 min before the alert's failure window, or 24 h before the alert when it gives none, up to 1 h after it; older failures are baseline). If the alert reports a `success_time`, the logged success within 2 min of it is chosen; otherwise the first from the alert's source IP, otherwise the first one. So a stray typo or a normal login elsewhere cannot become "the success" | `null` (unknown) when the alert names no account, no Wazuh search succeeded, a Wazuh search was truncated, or no complete Wazuh search **for the account or host** covered the window up to the alert time (a search for one source IP cannot see a success from another): "no success seen" is only a finding when the search could have seen it |
| failures for the account | Wazuh `auth_failure` in that window before the success | **brute force** = at least `BRUTE_FORCE_MIN` = **10** |
| source IP internal | address range (RFC 1918, loopback, link-local) | RFC 5737 lab ranges count as external |
| source in the account's baseline | `usual_source_ips` (inventory) + successful logins before the attack window | `null` if neither was looked up / seen |
| host criticality | `get_asset_context host=...` | `null` if the host is not in the inventory or was not looked up |
| post-login privileged actions | Wazuh `privilege` (sudo) by the account on the host after the success | ignored (neutral factor) when the inventory marks the account `privileged` **and** the login came from its baseline: routine admin work. From any other source it still counts |
| post-login account changes | Wazuh `account_change` on the host after the success | possible persistence |
| outbound after login | tshark sessions from the host to an external address after the success | with the destination's lookup_ip classification (**MOCK** intel), or `not_looked_up` / `failed` |
| other accounts targeted | Wazuh failures from the same source for other accounts | password spraying |
| source reputation | `lookup_ip` for the source (**MOCK** intel) | corroborates; never decides the level on its own |

## Severity: ordered rules (first match wins)

| Rule | Level | Condition |
|---|---|---|
| M2 | **medium** | Login outcome unknown: authentication logs unavailable, truncated or not covering the alert's window for the account or host, or the alert names no account (key evidence missing; reported as the gap `login_outcome_unknown`, so confidence cannot be high) |
| L1 / L0 | **low** | Failed logins **without** a successful login (L1), or no failures or successes at all (L0) |
| C1 | **critical** | Success after brute force (≥ 10 failures) **and** post-login sudo / account change **on a high- or critical-criticality host** |
| C2 | **critical** | Success after brute force **and** an outbound connection after the login to a destination **MOCK intel** classifies as malicious or suspicious |
| H2 | **high** | Success after failures **with** post-login sudo / account change / suspicious outbound, but C1/C2 not met (e.g. few failures, or host criticality unknown or lower) |
| H1 | **high** | Success after ≥ 10 failures from an **external** IP that is **not** (or not known to be) in the account's baseline, on a high-criticality host, no confirmed post-login activity |
| L2 | **low** | Benign explanation supported: success from a source **in the account's baseline**, fewer than 10 failures, no other accounts targeted, no external outbound with unknown reputation, nothing suspicious after the login |
| M1 | **medium** | Any other success after failures: the source is internal or known for the user but other signals don't fit L2, or key evidence (baseline, criticality) is missing |

Design choices:

- **Unknown host criticality caps C1 at high.** Persistence on an unknown host is serious, but "critical" needs the business context that is missing. The factor says so ("caps at high"), and the agent can argue for critical in its rationale.
- **Intel never decides alone, except C2.** The source IP's reputation is a corroborating factor. If the level is reached **only** through MOCK intel (C2 without C1, or H2 only because of a suspicious destination), `rests_on_mock_intel` is true, and that lowers confidence.
- **Failures without success stay low** (as the brief's rubric says), even 50 of them from a malicious IP. The factors still show the volume and the source, so an analyst can raise priority for hardening.

### Score

The score places an alert **inside its level's band**, so alerts of the same level can be ranked. It never changes the level.

| Level | Band |
|---|---|
| low | 0 – 24 |
| medium | 25 – 49 |
| high | 50 – 74 |
| critical | 75 – 100 |

`score = band_min + round(points / 120 × band_width)`, where `points` is the sum of factor weights, clipped to the band:

| Factor | Weight |
|---|---|
| successful login after failures | +30 |
| brute-force volume (≥ 10 failures, with a success) | +15 |
| failures only, no success | +10 |
| external source not in the baseline | +15 |
| source in the baseline | −20 |
| internal source, baseline unknown | −5 (an internal source known to be **outside** the baseline is neutral: possible lateral movement) |
| host criticality high/critical | +10 |
| post-login sudo | +15 |
| post-login account change | +15 |
| outbound to a malicious/suspicious destination (MOCK) | +15 |
| outbound with unknown reputation | +5 |
| other accounts targeted (spraying) | +5 |
| source classified malicious/suspicious (MOCK) | +5 |

Every factor is returned as `{factor, effect, points, basis, evidence_refs}`, where `basis` is logs / inventory / MOCK intel / missing evidence. So the rubric's reasoning traces back to evidence in the same way the agent's does.

## Confidence

Key sources (`correlate.KEY_SOURCES`):

| Key source | Status comes from |
|---|---|
| authentication logs (Wazuh) | a successful `search_logs` with source `wazuh` or `all` |
| network sessions (tshark) | a successful `search_logs` with source `tshark` or `all` |
| IP intelligence (lookup_ip, MOCK) | lookup of the source IP (not needed for an internal source) and of every external destination contacted after the login |
| host context | `get_asset_context host=...` found the host |
| account context | `get_asset_context account=...` found the account |

A key source has a **gap** when it failed, timed out, is missing (e.g. the host is not in the inventory), or was not queried. Other gaps (key_source `null`): a failed `search_cve`, a truncated search, a search that never covered the alert's failure window or the 30 minutes after the login, or a tshark/Wazuh comparison that was not possible although tshark was available.

| Confidence | Condition |
|---|---|
| **low** | **two or more** gaps (each key source counts once; each other gap counts once), **or** any unresolved conflict |
| **medium** | exactly **one** gap, **or** the severity level rests on MOCK intel alone |
| **high** | every key source answered, nothing failed or timed out, no conflict, and the level does not rest on MOCK intel alone |

Conflicts the correlation detects:

- **tshark vs Wazuh.** Login attempts from the source in the attack window vs SSH sessions from it. They are *consistent* when `sessions ≤ attempts ≤ sessions × 6`, because one SSH connection carries up to `MaxAuthTries` = 6 password attempts (the benign scenario's 5 attempts in 2 connections are consistent). Otherwise they are *inconsistent*, reported with the difference and possible explanations. Counts are only compared when a search covered every attempt and session in the window, so a narrow search is never mistaken for a conflict.
- **Alert vs logs.** The alert's `failed_attempts` vs the failures the logs show in the alert's window (only when a search covered that window), and the alert's success time vs the logged success (more than 2 s apart).

## Results on the scenarios

From `python scripts/run_scenarios.py` (mock LLM; the current results for every scenario are in [`test-report.md`](test-report.md); the Day 3 table below is kept for history, [`history/day3-scenarios.md`](history/day3-scenarios.md)):

| Scenario | Rubric rule | Severity | Confidence | Why |
|---|---|---|---|---|
| compromise | C1 | critical | high | 50 failures, success from 203.0.113.77 (not in baseline), sudo + `useradd backup_svc` on high-criticality fin-app-01; all sources consistent (54 attempts / 54 sessions) |
| benign | L2 | low | high | 4 failures then success from j.mehta's usual office IP 10.20.1.45; 5 attempts in 2 SSH sessions (consistent); nothing after |
| failures_only | L1 | low | high | 50 failures from a malicious (MOCK) external IP, no success |
| incomplete | H2 | high | low | success + sudo, but fin-app-02 is not in the inventory (caps at high) and the tshark export is missing: 2 gaps |
| tool_failure | C1 | critical | medium | same evidence as compromise, but lookup_ip timed out: reputation unknown, 1 key-source gap; critical rests on logs, not intel |
| conflicting | H1 | high | low | 51 Wazuh attempts but only 7 tshark sessions (more than 6 attempts per session would be needed): unresolved conflict |
