"""Deterministic severity and confidence rubric (Day 3). Documented in docs/severity.md.

Input: the output of correlate.correlate() (facts computed from THIS run's tool results).
No LLM. The agent states its own severity and confidence in submit_findings; this rubric is
the reference they are compared with (a disagreement must be explained, never overwritten).

Severity is decided by ordered rules (first match wins); the score only places the alert
inside its level's band, so two alerts of the same level can be ranked:
    low 0-24 | medium 25-49 | high 50-74 | critical 75-100
Confidence is separate from severity: it says how complete and consistent the evidence is.
"""
from __future__ import annotations

from soc_agent.correlate import BRUTE_FORCE_MIN, KEY_SOURCE_NAMES

SEVERITIES = ("low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
BANDS = {"low": (0, 24), "medium": (25, 49), "high": (50, 74), "critical": (75, 100)}
HIGH_CRITICALITY = ("high", "critical")
BAD_REPUTATION = ("malicious", "suspicious")
# factor weights (they order alerts inside a band; the level comes from the rules)
POINTS = {
    "success_after_failures": 30, "brute_force": 15, "failures_only": 10, "external_not_in_baseline": 15,
    "in_baseline": -20, "internal_source": -5, "host_high_criticality": 10, "privileged_action": 15,
    "account_change": 15, "outbound_suspicious": 15, "outbound_unknown": 5, "spraying": 5,
    "source_bad_reputation": 5,
}
MAX_POINTS = 120


def _f(factors: list, name: str, effect: str, refs: list[str], basis: str, points: int | None = None) -> None:
    factors.append({"factor": name, "effect": effect, "points": POINTS.get(points, 0) if isinstance(points, str)
                    else (points or 0), "basis": basis, "evidence_refs": list(dict.fromkeys(refs))})


def assess_severity(correlation: dict) -> dict:
    """{severity, score, rule, rests_on_mock_intel, factors[{factor, effect, points, basis, evidence_refs}]}."""
    s = correlation["signals"]
    refs = s["refs"]
    factors: list[dict] = []
    success = s["success_after_failures"]
    n_fail = s["failures_for_account"]
    brute = n_fail >= BRUTE_FORCE_MIN
    external = s["source_ip_internal"] is False
    base = s["source_in_baseline"]
    crit = s["host_criticality"]
    crit_high = crit in HIGH_CRITICALITY
    priv, changes = s["post_privileged_actions"], s["post_account_changes"]
    # sudo by an account the inventory marks privileged, from its own usual source, is routine work
    expected_sudo = bool(priv) and s.get("account_privileged") is True and base is True
    if expected_sudo:
        priv = 0
    out_bad = [d for d in s["post_outbound_external"] if d["classification"] in BAD_REPUTATION]
    out_unknown = [d for d in s["post_outbound_external"] if d["reputation_status"] != "ok"]
    spray = s["other_accounts_targeted"]
    rep = s["source_reputation"]

    # ---- factors (what the evidence says, with refs)
    if success:
        _f(factors, f"Successful login after {n_fail} failed login(s)", "raises", refs["success"] + refs["failures"],
           "logs", "success_after_failures")
    if brute:
        _f(factors, f"{n_fail} failures (>= {BRUTE_FORCE_MIN}): brute force / password guessing volume", "raises",
           refs["failures"], "logs", "brute_force" if success else 0)
    if success is False and n_fail:
        _f(factors, f"{n_fail} failed login(s) and no successful login", "raises (attempt only)", refs["failures"],
           "logs", "failures_only")
    if external and base is False:
        _f(factors, f"Source {s['source_ip']} is external and not in the account's baseline", "raises",
           refs["source"] + refs["baseline"], "logs + inventory", "external_not_in_baseline")
    elif base is True:
        _f(factors, f"Source {s['source_ip']} is in the account's baseline (usual IP / earlier logins)", "lowers",
           refs["baseline"], "logs + inventory", "in_baseline")
    elif s["source_ip_internal"] is True and base is None:
        _f(factors, f"Source {s['source_ip']} is internal (RFC 1918); account baseline unknown", "lowers",
           refs["source"], "address range", "internal_source")
    elif s["source_ip_internal"] is True:
        _f(factors, f"Source {s['source_ip']} is internal but NOT in the account's baseline (possible lateral "
           "movement)", "neutral", refs["source"] + refs["baseline"], "logs + inventory", 0)
    if base is None and s["source_ip"]:
        _f(factors, "Account baseline unknown (no account context and no earlier logins seen)", "unknown", [],
           "missing evidence", 0)
    if crit_high:
        _f(factors, f"Host criticality {crit}", "raises", refs["host"], "inventory", "host_high_criticality")
    elif crit is None:
        _f(factors, "Host criticality unknown (host not in the inventory or not looked up)",
           "caps at high (Critical via post-login activity needs a high-criticality host)", [], "missing evidence", 0)
    else:
        _f(factors, f"Host criticality {crit}", "neutral", refs["host"], "inventory", 0)
    if priv:
        _f(factors, f"{priv} privileged action(s) (sudo) by the account after the login", "raises", refs["privileged"],
           "logs", "privileged_action")
    elif expected_sudo:
        _f(factors, "sudo after the login by an account the inventory marks privileged, from its usual source",
           "neutral (expected for this account)", refs["privileged"] + refs["baseline"], "logs + inventory", 0)
    if changes:
        _f(factors, f"{changes} account change(s) on the host after the login (possible persistence)", "raises",
           refs["account_changes"], "logs", "account_change")
    if out_bad:
        _f(factors, "Outbound connection after the login to " + ", ".join(f"{d['dst_ip']} ({d['classification']})"
                                                                         for d in out_bad) + " per MOCK intel",
           "raises", refs["outbound"], "MOCK intel + tshark", "outbound_suspicious")
    if out_unknown:
        _f(factors, "Outbound connection after the login to " + ", ".join(d["dst_ip"] for d in out_unknown)
           + " with unknown reputation", "raises slightly; unknown", refs["outbound"], "tshark", "outbound_unknown")
    if spray:
        _f(factors, f"Same source also tried other account(s): {', '.join(spray)} (spraying)", "raises",
           refs["spraying"], "logs", "spraying")
    if rep.get("classification") in BAD_REPUTATION:
        _f(factors, f"Source classified {rep['classification']} (score {rep.get('score')}) by MOCK intel",
           "corroborates (MOCK intel, not decisive)", refs["source_reputation"], "MOCK intel", "source_bad_reputation")
    elif rep.get("status") in ("failed", "not_looked_up") and external:
        _f(factors, f"Reputation of {s['source_ip']} unknown (lookup_ip {rep.get('status').replace('_', ' ')})",
           "unknown", [], "missing evidence", 0)

    # ---- rules (first match wins)
    post = bool(priv or changes)
    mock_only = False
    if success is None:
        level, rule = "medium", ("M2: login outcome unknown - authentication logs unavailable or truncated (key "
                                 "evidence missing)")
    elif not success:
        level, rule = "low", ("L1: failed logins without a successful login" if n_fail
                              else "L0: no failed or successful logins found for the account")
    elif brute and ((post and crit_high) or out_bad):
        level = "critical"
        rule = ("C1: success after brute force AND post-login privilege/account activity on a high-criticality host"
                if post and crit_high else
                "C2: success after brute force AND outbound connection to a suspicious destination (MOCK intel)")
        mock_only = not (post and crit_high)
    elif post or out_bad:
        level, rule = "high", "H2: success after failures with post-login privilege/account/suspicious outbound activity"
        mock_only = not post
    elif brute and external and base is not True and crit_high:
        level, rule = "high", ("H1: success after many failures from an external IP not in the account's baseline, "
                               "high-criticality host, no confirmed post-login activity")
    elif base is True and not brute and not spray and not out_unknown:
        level, rule = "low", ("L2: benign explanation supported - success from the account's usual source after few "
                              "failures, no other accounts targeted, no suspicious activity after the login")
    else:
        level, rule = "medium", ("M1: success after failures, but the source is internal/known for the user, or key "
                                 "evidence is missing")
    points = sum(f["points"] for f in factors)
    lo, hi = BANDS[level]
    score = lo + max(0, min(hi - lo, round(max(points, 0) / MAX_POINTS * (hi - lo))))
    return {"severity": level, "score": score, "rule": rule, "rests_on_mock_intel": mock_only, "factors": factors}


def assess_confidence(correlation: dict, severity: dict | None = None) -> dict:
    """{confidence, reasons[]}: High only if every key source answered, nothing conflicts and the level
    does not rest on MOCK intel alone."""
    severity = severity or assess_severity(correlation)
    gaps, conflicts = correlation["gaps"], correlation["conflicts"]
    key = sorted({g["key_source"] for g in gaps if g["key_source"]})
    other = [g for g in gaps if not g["key_source"]]
    n = len(key) + len(other)
    reasons = [f"Key source problem: {KEY_SOURCE_NAMES[k]}: "
               + "; ".join(g["statement"] for g in gaps if g["key_source"] == k) for k in key]
    reasons += [f"Gap: {g['statement']}" for g in other]
    reasons += [f"Unresolved conflict: {c['statement']}" for c in conflicts]
    if severity["rests_on_mock_intel"]:
        reasons.append(f"The {severity['severity']} level rests on MOCK intelligence ({severity['rule'][:3]}).")
    if n >= 2 or conflicts:
        level = "low"
    elif n == 1 or severity["rests_on_mock_intel"]:
        level = "medium"
    else:
        level = "high"
        reasons.append("All key sources (" + ", ".join(KEY_SOURCE_NAMES[k] for k in KEY_SOURCE_NAMES)
                       + ") answered, are consistent and nothing timed out.")
    return {"confidence": level, "reasons": reasons, "key_source_gaps": key, "other_gaps": len(other),
            "conflicts": len(conflicts)}


def rubric(correlation: dict) -> dict:
    sev = assess_severity(correlation)
    return {"severity": sev, "confidence": assess_confidence(correlation, sev)}
