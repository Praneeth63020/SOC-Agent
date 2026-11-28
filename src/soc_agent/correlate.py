"""Deterministic correlation (Day 3): this run's tool results -> timeline, facts, gaps, conflicts.

No LLM is involved. The input is ONLY:
  - the results the evidence tools returned in THIS run (RunContext.evidence_results),
  - the audit trail of the run (which calls failed, timed out or were never made),
  - the alert under investigation (only to know which account, host and source IP the
    investigation is about; nothing the alert claims is used as evidence).
Every timeline entry and every fact carries the evidence_refs it rests on, so a reader (and
submit_findings) can trace each statement back to a tool result.

Phase labels are POSITIONS relative to the failure window, not verdicts:
  baseline          before the first failed login of the attack window
  attack            the failed logins (and anything between them and the success)
  compromise        the first successful login after the failures (and the TCP session that
                    carried it); in a benign case this is simply "the success after failures"
  post_compromise   everything after that success
  post_attack       after the last failure when there was no success
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

from soc_agent.tools.evidence import INTERNAL_NETS, parse_utc

EVIDENCE_TOOLS = ("search_logs", "lookup_ip", "search_cve", "get_asset_context")
KEY_SOURCES = ("auth_logs", "network_sessions", "ip_intel", "host_context", "account_context")
KEY_SOURCE_NAMES = {
    "auth_logs": "authentication logs (Wazuh)",
    "network_sessions": "network sessions (tshark)",
    "ip_intel": "IP intelligence (lookup_ip, MOCK feed)",
    "host_context": "host context (asset inventory)",
    "account_context": "account context (asset inventory)",
}
BRUTE_FORCE_MIN = 10        # failed logins before a success that count as brute force / password guessing
MAX_AUTH_TRIES = 6          # sshd default MaxAuthTries: password attempts one SSH connection can carry
SESSION_LEAD_S = 30         # a TCP session may start this long before its first logged attempt
SESSION_TRAIL_S = 2
SUMMARY_MAX = 160
ATTACK_LEAD_MIN = 15        # failures this long before the alert's failure window still belong to it (spraying lead-in)
SUCCESS_MATCH_S = 120       # a logged success this close to the alert's success_time is "the" success
PHASES = ("baseline", "attack", "compromise", "post_compromise", "post_attack")
PHASE_DEFINITIONS = {
    "baseline": "before the first failed login of the attack window",
    "attack": "the failed logins, up to the first success after them",
    "compromise": "the first successful login after the failures (and the TCP session carrying it); a position, "
                  "not a verdict",
    "post_compromise": "after that successful login",
    "post_attack": "after the last failure, when no success followed",
}
_SESSION = re.compile(r"(?P<src>[\d.]+):(?P<sport>\d+) -> (?P<dst>[\d.]+):(?P<dport>\d+).*duration (?P<dur>[\d.]+) s, "
                      r"(?P<bytes>\d+) bytes")


# ------------------------------------------------------------------------------ helpers
def _t(ev_or_time: dict | str) -> datetime:
    return parse_utc(ev_or_time["time"] if isinstance(ev_or_time, dict) else ev_or_time)


def _internal(ip: str | None) -> bool | None:
    if not ip:
        return None
    try:
        return any(ipaddress.IPv4Address(ip) in n for n in INTERNAL_NETS)
    except ValueError:
        return None


def _lc(v: Any) -> str:
    return str(v).lower() if v is not None else ""


def _hhmmss(ev: dict) -> str:
    return ev["time"][11:19]


def _span(evs: list[dict]) -> str:
    if not evs:
        return ""
    return _hhmmss(evs[0]) if len(evs) == 1 else f"{_hhmmss(evs[0])}-{_hhmmss(evs[-1])}"


def _ends(evs: list[dict]) -> list[str]:
    """First and last ref of a sorted event list (the usual pair to cite)."""
    if not evs:
        return []
    return list(dict.fromkeys([evs[0]["evidence_ref"], evs[-1]["evidence_ref"]]))


def _session(ev: dict) -> dict | None:
    m = _SESSION.search(ev.get("summary") or "")
    if not m:
        return None
    return {"src_port": int(m["sport"]), "duration_s": float(m["dur"]), "bytes": int(m["bytes"])}


def _call_key(tool: str, args: Any) -> str:
    return tool + json.dumps(args, sort_keys=True, default=str)


def _search_covers(args: dict, result: dict, source: str, t0: datetime, t1: datetime,
                   allowed: dict[str, set], event_types: set[str]) -> bool:
    """Did this successful search_logs call see EVERY event of `source` in [t0, t1] that matches the
    entity values in `allowed`? (Used before comparing counts, so a narrow search is never mistaken
    for missing events.)"""
    if args.get("source") not in (source, "all") or result.get("truncated"):
        return False
    if args.get("event_type", "any") not in event_types | {"any"}:
        return False
    for key in ("account", "host", "src_ip", "dst_ip", "dst_port"):
        if key in args and _lc(args[key]) not in {_lc(v) for v in allowed.get(key, set()) if v is not None}:
            return False
    try:
        if "start" in args and parse_utc(args["start"]) > t0:
            return False
        if "end" in args:
            end = parse_utc(args["end"])
            if "." not in args["end"]:          # same rule as search_logs: a whole-second end covers that second
                end = end.replace(microsecond=999999)
            if end < t1:
                return False
    except ValueError:
        return False
    return True


def _pick_success(acct_succ: list[dict], acct_fails: list[dict], obs: dict, alert_src: str | None,
                  on_host) -> dict | None:
    """The success that belongs to this alert: after its first failure, on its host; the one at the alert's
    success_time if it reports one, else the first from the alert's source IP, else the first one."""
    if not acct_fails:
        return None
    cands = [s for s in acct_succ if s["time"] > acct_fails[0]["time"] and (on_host is None or on_host(s))]
    if not cands:
        return None
    st = _obs_time(obs, "success_time")
    if st:
        near = [s for s in cands if abs((_t(s) - st).total_seconds()) <= SUCCESS_MATCH_S]
        if near:
            return min(near, key=lambda s: abs((_t(s) - st).total_seconds()))
    return next((s for s in cands if alert_src and s["src_ip"] == alert_src), cands[0])


def _obs_time(obs: dict, key: str) -> datetime | None:
    try:
        return parse_utc(obs[key]) if obs.get(key) else None
    except (TypeError, ValueError):
        return None


def _attack_window(alert: dict, obs: dict) -> tuple[datetime | None, datetime | None, datetime | None]:
    """(start, alert time, end) of the window whose failures belong to THIS alert: from ATTACK_LEAD_MIN minutes
    before the alert's failure window (or 24 h before the alert when it gives none) to 1 h after the alert."""
    if not isinstance(alert.get("timestamp"), str):
        return None, None, None
    try:
        anchor = parse_utc(str(alert.get("timestamp")))
    except ValueError:
        return None, None, None
    start = _obs_time(obs, "failure_window_start")
    lo = (start - timedelta(minutes=ATTACK_LEAD_MIN)) if start and start <= anchor else anchor - timedelta(hours=24)
    return lo, anchor, anchor + timedelta(hours=1)


# ---------------------------------------------------------------------------- correlate
def correlate(alert: dict, evidence_results: list[dict], tool_calls: list[dict]) -> dict:
    """Timeline, facts, gaps and conflicts from this run's tool results (see module docstring)."""
    ents = alert.get("entities") or {}
    obs = alert.get("observations") or {}
    acct = _lc(ents.get("account")) or None
    host = ents.get("host")
    alert_src = ents.get("src_ip")
    port = ents.get("dst_port") or 22

    # ---- what the tools returned in this run
    events: dict[str, dict] = {}
    searches: list[tuple[dict, dict]] = []
    intel: dict[str, dict] = {}
    host_recs: dict[str, dict] = {}
    acct_recs: dict[str, dict] = {}
    not_found: dict[str, list[str]] = defaultdict(list)
    malformed = 0
    for r in evidence_results:
        tool, args, res = r["tool"], r.get("arguments") or {}, r["result"]
        if tool == "search_logs":
            searches.append((args, res))
            malformed = max(malformed, res.get("malformed_lines_skipped", 0))
            for e in res.get("events", []):
                events.setdefault(e["evidence_ref"], e)
        elif tool == "lookup_ip":
            intel[res["ip"]] = res
        elif tool == "get_asset_context":
            if res.get("found"):
                (host_recs if res["kind"] == "host" else acct_recs)[_lc(res["record"]["name"])] = res
            else:
                not_found[res["kind"]].append(res["query"])
    ok_keys = {_call_key(r["tool"], r.get("arguments")) for r in evidence_results}
    failed = [c for c in tool_calls if c["tool"] in EVIDENCE_TOOLS and c["status"] in ("timeout", "error")
              and _call_key(c["tool"], c.get("arguments")) not in ok_keys]     # not recovered by a retry

    host_res = host_recs.get(_lc(host)) or next(
        (h for h in host_recs.values() if ents.get("dst_ip") and h["record"].get("ip") == ents.get("dst_ip")), None)
    host_ip = ents.get("dst_ip") or (host_res["record"].get("ip") if host_res else None)
    acct_res = acct_recs.get(acct or "")

    def on_host(e: dict) -> bool:
        return bool((host and _lc(e.get("host")) == _lc(host)) or (host_ip and e.get("dst_ip") == host_ip))

    evs = sorted(events.values(), key=lambda e: (e["time"], e["source"], e["evidence_ref"]))
    wazuh_ok = any(a.get("source") in ("wazuh", "all") for a, _ in searches)
    tshark_ok = any(a.get("source") in ("tshark", "all") for a, _ in searches)
    fails = [e for e in evs if e["event_type"] == "auth_failure"]
    acct_succ = [e for e in evs if e["event_type"] == "auth_success" and acct and _lc(e["account"]) == acct]
    # Only failures around the alert form the attack window: an old stray typo (days earlier) must not make
    # that day's normal login "the success after failures". Older failures stay in the timeline as baseline.
    win_lo, anchor, win_hi = _attack_window(alert, obs)
    in_window = (lambda e: win_lo <= _t(e) <= win_hi) if anchor else (lambda e: True)
    acct_fails = [e for e in fails if acct and _lc(e["account"]) == acct and in_window(e)]

    success = _pick_success(acct_succ, acct_fails, obs, alert_src, on_host if (host or host_ip) else None)
    if success:
        src = success["src_ip"]
    elif alert_src:
        src = alert_src
    else:
        src = Counter(e["src_ip"] for e in acct_fails if e["src_ip"]).most_common(1)[0][0] if acct_fails else None
    src_fails = [e for e in fails if src and e["src_ip"] == src and in_window(e)]
    fails_before = [e for e in acct_fails if not success or e["time"] < success["time"]]
    attack_evs = sorted({e["evidence_ref"]: e for e in acct_fails + src_fails}.values(), key=lambda e: e["time"])
    attack_start = attack_evs[0]["time"] if attack_evs else None
    # "no success" is only a finding if a complete Wazuh search for the ACCOUNT or HOST covered the alert's window up
    # to the alert time (a search for one source IP cannot see a success from another one); a truncated or too
    # narrow search may have cut the success off: then the outcome is unknown, not false
    wazuh_truncated = any(a.get("source") in ("wazuh", "all") and r.get("truncated") for a, r in searches)
    outcome_covered = anchor is None or any(
        _search_covers(a, r, "wazuh", _obs_time(obs, "failure_window_start") or anchor, anchor,
                       {"account": {acct}, "host": {host, host_ip}, "dst_ip": {host_ip}}, {"auth_success"})
        for a, r in searches)
    outcome_reason = None
    if success is not None:
        success_state: bool | None = True
    elif not acct:
        success_state = None
        outcome_reason = "The alert names no account, so a success after failures cannot be tied to one."
    elif not wazuh_ok:
        success_state = None
    elif wazuh_truncated:
        success_state = None
        outcome_reason = ("A Wazuh search was truncated, so a successful login may have been cut off: the login "
                          "outcome is unknown.")
    elif not outcome_covered:
        success_state = None
        outcome_reason = (f"No complete Wazuh search for account {ents.get('account')} or host {host} covered the "
                          f"alert's window up to the alert time ({alert.get('timestamp')}): the login outcome is "
                          "unknown.")
    else:
        success_state = False

    # ---- the login session (tshark) that carried the success
    login_session = None
    if success:
        st = _t(success)
        for e in evs:
            s = _session(e) if e["source"] == "tshark" else None
            if (s and e["src_ip"] == success["src_ip"] and (not host_ip or e["dst_ip"] == host_ip)
                    and e.get("dst_port") == port and _t(e) <= st <= _t(e) + timedelta(seconds=s["duration_s"])):
                login_session = {**e, **s}
                break

    # ---- baseline for the account
    baseline_ips: dict[str, list[str]] = defaultdict(list)
    if acct_res:
        for ip in acct_res["record"].get("usual_source_ips", []):
            baseline_ips[ip].append(acct_res["evidence_ref"])
    cutoff = attack_start or (success["time"] if success else None)
    earlier_succ = [e for e in acct_succ if cutoff and e["time"] < cutoff]
    for e in earlier_succ:
        if e["src_ip"]:
            baseline_ips[e["src_ip"]].append(e["evidence_ref"])
    if src is None or (acct_res is None and not earlier_succ):
        in_baseline = None
    else:
        in_baseline = src in baseline_ips

    # ---- spraying: other accounts the same source tried
    others: dict[str, list[dict]] = defaultdict(list)
    for e in src_fails:
        if e["account"] and _lc(e["account"]) != acct:
            others[e["account"]].append(e)

    # ---- after the success
    after = [e for e in evs if success and e["time"] > success["time"]]
    priv = [e for e in after if e["event_type"] == "privilege" and on_host(e)
            and (not acct or _lc(e["account"]) == acct)]
    changes = [e for e in after if e["event_type"] == "account_change" and on_host(e)]
    outbound = [e for e in after if e["source"] == "tshark" and host_ip and e["src_ip"] == host_ip
                and _internal(e["dst_ip"]) is False]
    failed_lookups = {(c.get("arguments") or {}).get("ip") for c in failed if c["tool"] == "lookup_ip"}

    def rep(ip: str | None) -> dict:
        if ip in intel:
            r = intel[ip]
            return {"status": "ok", "classification": r["classification"], "found": r["found"],
                    "score": r.get("reputation_score"), "categories": r.get("categories", []),
                    "evidence_refs": [r["evidence_ref"]] if r.get("evidence_ref") else [], "mock": True}
        if ip in failed_lookups:
            return {"status": "failed", "classification": None, "evidence_refs": []}
        return {"status": "not_looked_up", "classification": None, "evidence_refs": []}

    src_rep = rep(src) if src else {"status": "not_looked_up", "classification": None, "evidence_refs": []}
    out_dsts = []
    for dst in dict.fromkeys(e["dst_ip"] for e in outbound):
        sess = [e for e in outbound if e["dst_ip"] == dst]
        out_dsts.append({"dst_ip": dst, "sessions": len(sess), "first_time": sess[0]["time"],
                         "bytes": sum((_session(e) or {}).get("bytes", 0) for e in sess),
                         "dst_ports": sorted({e["dst_port"] for e in sess if e["dst_port"]}),
                         "reputation": rep(dst), "evidence_refs": [e["evidence_ref"] for e in sess]})

    # ---- tshark sessions vs Wazuh attempts from the source during the attack window
    tw = _tshark_vs_wazuh(evs, searches, src, host, host_ip, port, success, tshark_ok, attack_start, acct)

    # ---- timeline (only events related to the subject)
    related_ips = {ip for ip in (src, alert_src, host_ip) if ip} | {d["dst_ip"] for d in out_dsts}
    last_attack = attack_evs[-1]["time"] if attack_evs else None
    compromise_refs = {r for r in ((success or {}).get("evidence_ref"), (login_session or {}).get("evidence_ref")) if r}

    lead_start = (_t(attack_start) - timedelta(seconds=SESSION_LEAD_S)) if attack_start else None

    def phase(e: dict) -> str:
        if attack_start is None:
            return "baseline"
        if e["time"] < attack_start:        # a TCP session opens a moment before its first logged attempt
            lead = e["source"] == "tshark" and e["src_ip"] == src and _t(e) >= lead_start
            if not lead:
                return "baseline"
        if e["evidence_ref"] in compromise_refs:
            return "compromise"
        if success:
            return "attack" if e["time"] <= success["time"] else "post_compromise"
        return "attack" if e["time"] <= last_attack else "post_attack"

    timeline, excluded = [], 0
    for e in evs:
        if not ((acct and _lc(e["account"]) == acct) or e["src_ip"] in related_ips or e["dst_ip"] in related_ips
                or (host and _lc(e["host"]) == _lc(host))):
            excluded += 1
            continue
        timeline.append({"time": e["time"], "phase": phase(e), "source": e["source"], "event_type": e["event_type"],
                         "account": e["account"], "host": e["host"], "src_ip": e["src_ip"], "dst_ip": e["dst_ip"],
                         "summary": e["summary"][:SUMMARY_MAX], "evidence_ref": e["evidence_ref"]})

    # ---- facts
    facts: list[dict] = []

    def fact(fid: str, statement: str, refs: list[str], **data: Any) -> None:
        facts.append({"id": fid, "statement": statement, "evidence_refs": list(dict.fromkeys(refs)), "data": data})

    by_acct: dict[str, list[dict]] = defaultdict(list)
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in fails:
        if e["account"]:
            by_acct[e["account"]].append(e)
        if e["src_ip"]:
            by_ip[e["src_ip"]].append(e)
    if fails:
        fact("failures_by_account",
             "Failed logins by account: " + "; ".join(
                 f"{a} {len(v)} ({_span(v)} UTC on {v[0]['time'][:10]}, from {', '.join(sorted({x['src_ip'] or '?' for x in v}))})"
                 for a, v in sorted(by_acct.items(), key=lambda kv: -len(kv[1]))),
             [r for v in by_acct.values() for r in _ends(v)],
             counts={a: len(v) for a, v in by_acct.items()},
             first={a: v[0]["time"] for a, v in by_acct.items()}, last={a: v[-1]["time"] for a, v in by_acct.items()})
        fact("failures_by_src_ip",
             "Failed logins by source IP: " + "; ".join(
                 f"{ip} {len(v)} ({_span(v)} UTC, accounts {', '.join(sorted({x['account'] or '?' for x in v}))})"
                 for ip, v in sorted(by_ip.items(), key=lambda kv: -len(kv[1]))),
             [r for v in by_ip.values() for r in _ends(v)], counts={ip: len(v) for ip, v in by_ip.items()})
    elif wazuh_ok:
        fact("failures_by_account", "No failed logins were returned by the searches in this run.", [], counts={})

    gap_s = None
    if success:
        last_f = fails_before[-1] if fails_before else None
        gap_s = round((_t(success) - _t(last_f)).total_seconds(), 1) if last_f else None
        same = bool(last_f and last_f["src_ip"] == success["src_ip"])
        fact("success_after_failures",
             f"{success['account']} logged in successfully at {success['time']} from {success['src_ip']} after "
             f"{len(fails_before)} failed login(s) ({_span(fails_before)} UTC); "
             f"{'same' if same else 'different'} source IP as the last failure; {gap_s} s after the last failure.",
             [success["evidence_ref"], *_ends(fails_before)],
             failures_before=len(fails_before), same_ip=same, seconds_after_last_failure=gap_s,
             success_time=success["time"], src_ip=success["src_ip"])
    elif acct_fails:
        fact("success_after_failures",
             f"No successful login for {ents.get('account')} after the {len(acct_fails)} failed login(s) in the "
             f"returned evidence (failures {_span(acct_fails)} UTC)"
             + ("." if success_state is False else
                "; a Wazuh search was truncated, so a later success may have been cut off (outcome unknown)."
                if wazuh_truncated else
                "; no complete Wazuh search covered the alert's window up to the alert time (outcome unknown)."),
             _ends(acct_fails),
             failures_before=len(acct_fails), same_ip=None, seconds_after_last_failure=None)

    if login_session:
        fact("login_session",
             f"The TCP session that carried the successful login ({login_session['src_ip']}:"
             f"{login_session['src_port']} -> {login_session['dst_ip']}:{login_session['dst_port']}) started "
             f"{login_session['time']} and lasted {login_session['duration_s']:g} s ({login_session['bytes']} bytes).",
             [login_session["evidence_ref"], success["evidence_ref"]],
             duration_s=login_session["duration_s"], bytes=login_session["bytes"])

    if in_baseline is not None:
        refs = [acct_res["evidence_ref"]] if acct_res else []
        refs += [e["evidence_ref"] for e in earlier_succ][-3:]
        usual = acct_res["record"].get("usual_source_ips", []) if acct_res else []
        fact("source_ip_baseline",
             f"{src} {'IS' if in_baseline else 'is NOT'} in {ents.get('account')}'s baseline "
             f"(usual source IPs in the inventory: {', '.join(usual) or 'none recorded / not looked up'}; "
             f"{len(earlier_succ)} earlier successful login(s) before the attack window, from "
             f"{', '.join(sorted({e['src_ip'] for e in earlier_succ if e['src_ip']})) or 'none'}).",
             refs + (baseline_ips.get(src, [])[:2] if in_baseline else []),
             in_baseline=in_baseline, usual_source_ips=usual, earlier_successes=len(earlier_succ))
    if src:
        fact("source_ip_type",
             f"{src} is {'an internal (RFC 1918) address' if _internal(src) else 'an external (non-RFC 1918) address'}.",
             ([success["evidence_ref"]] if success else _ends(src_fails)[:1]),     # logs, never the intel ref
             internal=_internal(src))
    if src_rep["status"] == "ok":
        r = src_rep
        text = (f"MOCK intel: {src} is classified {r['classification']}"
                + (f" (score {r['score']}; {', '.join(r['categories'])})" if r["found"] else
                   (" (internal address, not looked up in the feed)" if r["classification"] == "internal" else
                    " (no record in the MOCK feed; absence of data is not evidence of benign)")) + ".")
        fact("source_ip_reputation", text, r["evidence_refs"], **{k: r[k] for k in ("classification", "score")}, mock=True)
    if others:
        fact("other_accounts_targeted",
             f"{src} also failed logins for other accounts: "
             + "; ".join(f"{a} {len(v)} ({_span(v)} UTC)" for a, v in sorted(others.items())) + ".",
             [r for v in others.values() for r in _ends(v)], accounts=sorted(others), counts={a: len(v) for a, v in others.items()})
    elif src and src_fails:
        fact("other_accounts_targeted", f"No other account was targeted by {src} in the returned evidence.",
             _ends(src_fails), accounts=[])
    if host_res:
        rec = host_res["record"]
        fact("host_context",
             f"{rec['name']} ({rec['ip']}): {rec['role']}; criticality {rec['criticality']}; internet_exposed "
             f"{rec['internet_exposed']}.", [host_res["evidence_ref"]],
             criticality=rec["criticality"], internet_exposed=rec["internet_exposed"])
    if acct_res:
        rec = acct_res["record"]
        fact("account_context",
             f"{rec['name']}: {rec['role']}; privileged {rec['privileged']}; usual login method "
             f"{rec.get('usual_login_method', 'unknown')}" + (f"; note: {rec['notes'].rstrip('.')}" if rec.get("notes") else "")
             + ".",
             [acct_res["evidence_ref"]], privileged=rec["privileged"])
    if success:
        fact("post_compromise_privileged",
             (f"{len(priv)} privileged action(s) by {ents.get('account')} on {host} after the login: "
              + "; ".join(f"{_hhmmss(e)} {e['summary'].split('|', 1)[-1].strip()[:90]}" for e in priv)) if priv else
             f"No privileged (sudo) action by {ents.get('account')} on {host} after the login in the returned evidence.",
             [e["evidence_ref"] for e in priv] or [success["evidence_ref"]], count=len(priv))
        fact("post_compromise_account_changes",
             (f"{len(changes)} account change(s) on {host} after the login: "
              + "; ".join(f"{_hhmmss(e)} {e['summary'].split('|', 1)[-1].strip()[:90]}" for e in changes)) if changes else
             f"No account changes on {host} after the login in the returned evidence.",
             [e["evidence_ref"] for e in changes] or [success["evidence_ref"]], count=len(changes))
        if out_dsts:
            # the connection (tshark) and the destination's reputation (MOCK intel) are separate facts: a fact never
            # pairs an intel ref with a statement that does not say "MOCK intel" (a live model copied such pairs)
            fact("post_compromise_outbound",
                 f"{host} opened outbound connection(s) to external address(es) after the login: "
                 + "; ".join(f"{d['dst_ip']} port(s) {d['dst_ports']} at {d['first_time']} ({d['sessions']} session(s), "
                             f"{d['bytes']} bytes)" for d in out_dsts) + ".",
                 [r for d in out_dsts for r in d["evidence_refs"]],
                 destinations=[{k: d[k] for k in ("dst_ip", "sessions", "bytes", "dst_ports")} |
                               {"classification": d["reputation"]["classification"],
                                "reputation_status": d["reputation"]["status"]} for d in out_dsts])
            known_dst = [d for d in out_dsts if d["reputation"]["status"] == "ok"]
            if known_dst:
                fact("outbound_destination_reputation",
                     "; ".join(f"MOCK intel: {d['dst_ip']} is classified {d['reputation']['classification']}"
                               + (f" (score {d['reputation']['score']}; {', '.join(d['reputation']['categories'])})"
                                  if d["reputation"].get("score") is not None else "") for d in known_dst) + ".",
                     [r for d in known_dst for r in d["reputation"]["evidence_refs"]],
                     destinations=[d["dst_ip"] for d in known_dst], mock=True)
        else:
            later = [e for e in after if on_host(e) or (e["src_ip"] == host_ip)][:3]
            fact("post_compromise_outbound",
                 f"No outbound connection from {host} to an external address after the login in the returned "
                 f"evidence{' (tshark sessions were not available)' if not tshark_ok else ''}.",
                 [e["evidence_ref"] for e in later] or [success["evidence_ref"]], destinations=[])
    if tw["status"] != "not_comparable":
        fact("tshark_vs_wazuh", tw["statement"], tw["evidence_refs"],
             **{k: tw[k] for k in ("status", "wazuh_attempts", "tshark_sessions", "difference")})

    # ---- key sources, gaps, conflicts
    sources = _source_status(failed, src, src_rep, out_dsts, host, host_res, not_found, acct_res, ents, tshark_ok,
                             wazuh_ok)
    gaps = []
    for key in KEY_SOURCES:
        s = sources[key]
        if s["status"] not in ("ok", "not_applicable"):
            gaps.append({"id": f"{key}_{s['status']}", "key_source": key, "statement": s["detail"]})
    if outcome_reason and sources["auth_logs"]["status"] == "ok":
        gaps.append({"id": "login_outcome_unknown", "key_source": "auth_logs", "statement": outcome_reason})
    for c in failed:
        if c["tool"] == "search_cve":
            gaps.append({"id": "search_cve_failed", "key_source": None,
                         "statement": f"search_cve {c['status']} ({json.dumps(c.get('arguments'))}): vulnerability "
                                      "data for the host is unknown."})
    for a, r in searches:
        if r.get("truncated"):
            gaps.append({"id": "search_truncated", "key_source": None,
                         "statement": f"search_logs {json.dumps(a)} returned only {r['returned']} of "
                                      f"{r['total_matched']} matching events; correlation sees only returned events."})
    if tw["status"] == "not_comparable" and tw.get("reason") and sources["network_sessions"]["status"] == "ok":
        gaps.append({"id": "tshark_wazuh_not_comparable", "key_source": None, "statement": tw["reason"]})

    follow_ups = _coverage(gaps, obs, ents, searches, acct, host, host_ip, src, src_rep, out_dsts, success, acct_fails,
                           sources, tshark_ok)
    if tw["status"] == "not_comparable" and src and attack_evs and tshark_ok and wazuh_ok:
        t_lo = _t(attack_evs[0]) - timedelta(minutes=1)
        t_hi = (_t(success) if success else _t(attack_evs[-1])) + timedelta(minutes=1)
        follow_ups.append(f"search_logs source=all src_ip={src} start={t_lo:%Y-%m-%dT%H:%M:%SZ} "
                          f"end={t_hi:%Y-%m-%dT%H:%M:%SZ} limit=200  (both sources over the attack window, so tshark "
                          "sessions can be compared with Wazuh attempts)")
    if outcome_reason and acct and anchor and not any("cover the alert's failure window" in x for x in follow_ups):
        lo = _obs_time(obs, "failure_window_start") or (anchor - timedelta(hours=1))
        follow_ups.insert(0, f"search_logs source=wazuh account={ents.get('account')} start={lo:%Y-%m-%dT%H:%M:%SZ} "
                             f"end={anchor + timedelta(hours=1):%Y-%m-%dT%H:%M:%SZ} limit=200  (login outcome)")

    conflicts = []
    if tw["status"] == "inconsistent":
        conflicts.append({"id": "tshark_vs_wazuh", "statement": tw["statement"], "evidence_refs": tw["evidence_refs"],
                          "possible_explanations": tw["explanations"]})
    conflicts += _alert_vs_logs(obs, searches, fails_before if success else acct_fails, success, acct, host,
                                host_ip, alert_src)

    notes = []
    if malformed:
        notes.append(f"{malformed} malformed log line(s) were skipped by search_logs; their content is unknown.")
    if excluded:
        notes.append(f"{excluded} returned event(s) unrelated to {ents.get('account')} / {host} / {src} were left "
                     "out of the timeline.")

    signals = {
        "auth_logs_available": wazuh_ok,
        "success_after_failures": success_state,
        "failures_for_account": len(fails_before) if success else len(acct_fails),
        "failures_from_source": len(src_fails),
        "source_ip": src,
        "source_ip_internal": _internal(src),
        "source_in_baseline": in_baseline,
        "seconds_last_failure_to_success": gap_s,
        "other_accounts_targeted": sorted(others),
        "host_found": host_res is not None,
        "host_criticality": host_res["record"]["criticality"] if host_res else None,
        "account_privileged": acct_res["record"].get("privileged") if acct_res else None,
        "host_internet_exposed": host_res["record"]["internet_exposed"] if host_res else None,
        "post_privileged_actions": len(priv),
        "post_account_changes": len(changes),
        "post_outbound_external": [{"dst_ip": d["dst_ip"], "classification": d["reputation"]["classification"],
                                    "reputation_status": d["reputation"]["status"]} for d in out_dsts],
        "source_reputation": {k: src_rep.get(k) for k in ("status", "classification", "score")},
        "tshark_wazuh": tw["status"],
        "baseline_ips": sorted(baseline_ips),
        "refs": {
            "success": [success["evidence_ref"]] if success else [],
            "failures": _ends(fails_before if success else acct_fails),
            "baseline": ([acct_res["evidence_ref"]] if acct_res else []) + [e["evidence_ref"] for e in earlier_succ][-2:],
            "source": ([success["evidence_ref"]] if success else _ends(src_fails)[:1]),
            "host": [host_res["evidence_ref"]] if host_res else [],
            "privileged": [e["evidence_ref"] for e in priv],
            "account_changes": [e["evidence_ref"] for e in changes],
            "outbound": [r for d in out_dsts for r in d["evidence_refs"][:2] + d["reputation"]["evidence_refs"]],
            "source_reputation": src_rep["evidence_refs"],
            "spraying": [r for v in others.values() for r in _ends(v)],
            "post_login": [e["evidence_ref"] for e in after if on_host(e) or e["src_ip"] == host_ip][:3],
        },
    }
    return {
        "subject": {"account": ents.get("account"), "host": host, "host_ip": host_ip, "alert_src_ip": alert_src,
                    "source_ip": src, "alert_id": alert.get("alert_id")},
        "phase_definitions": PHASE_DEFINITIONS,
        "timeline": timeline,
        "facts": facts,
        "gaps": gaps,
        "conflicts": conflicts,
        "sources": sources,
        "signals": signals,
        "notes": notes,
        "suggested_follow_ups": follow_ups,
        "evidence_basis": {"tool_results_used": sum(r["tool"] in EVIDENCE_TOOLS for r in evidence_results),
                           "events_seen": len(evs),
                           "timeline_events": len(timeline), "failed_calls": len(failed)},
        "method": "deterministic (no LLM); computed only from tool results returned in this run",
        "data_label": "derived from SYNTHETIC logs/assets and MOCK intel",
    }


def _coverage(gaps, obs, ents, searches, acct, host, host_ip, src, src_rep, out_dsts, success, acct_fails, sources,
              tshark_ok) -> list[str]:
    """Deterministic coverage checks: evidence the searches in this run did not cover. Each adds a gap
    (key_source None) where it limits the assessment, and a concrete follow-up call the agent may make."""
    follow: list[str] = []
    start, end = obs.get("failure_window_start"), obs.get("failure_window_end")
    if start and end and sources["auth_logs"]["status"] == "ok":
        try:
            t0, t1 = parse_utc(start), parse_utc(end)
        except (TypeError, ValueError):
            t0 = t1 = None
        allowed = {"account": {acct}, "host": {host, host_ip}, "src_ip": {ents.get("src_ip")}, "dst_ip": {host_ip}}
        if t0 and not any(_search_covers(a, r, "wazuh", t0, t1, allowed, {"auth_failure"}) for a, r in searches):
            gaps.append({"id": "alert_window_not_covered", "key_source": None,
                         "statement": f"No successful search covered the alert's failure window {start} - {end} "
                                      f"(the alert reports {obs.get('failed_attempts', '?')} failures; the searches "
                                      f"returned {len([e for e in acct_fails if t0 <= _t(e) <= t1])} in that window)."})
            follow.append(f"search_logs source=wazuh account={ents.get('account')} start={start[:19]}Z "
                          f"end={end[:19]}Z limit=200  (cover the alert's failure window)")
    if success and host and sources["auth_logs"]["status"] == "ok":
        st = _t(success)
        allowed = {"host": {host, host_ip}, "dst_ip": {host_ip}}
        wz = any(_search_covers(a, r, "wazuh", st, st + timedelta(minutes=30), allowed, set()) for a, r in searches)
        ts = not tshark_ok or any(_search_covers(a, r, "tshark", st, st + timedelta(minutes=30),
                                                 {"host": {host, host_ip}, "src_ip": {host_ip}}, set())
                                  for a, r in searches)
        if not (wz and ts):
            missing = " and ".join(x for x, ok in (("Wazuh (sudo, new accounts)", wz),
                                                   ("tshark (outbound sessions)", ts)) if not ok)
            gaps.append({"id": "post_login_not_covered", "key_source": None,
                         "statement": f"Activity on {host} in the 30 minutes after the login ({success['time']}) was "
                                      f"not fully searched in {missing}: post-login actions may be missing."})
            follow.append(f"search_logs source={'all' if not (wz or ts) else ('wazuh' if not wz else 'tshark')} "
                          f"host={host} start={success['time'][:19]}Z limit=200  (no account, port or event_type "
                          "filter, so sudo, new accounts and outbound sessions are all included)")
    if sources["network_sessions"]["status"] == "not_queried" and src:
        follow.append(f"search_logs source=tshark src_ip={src} limit=200  (session counts, timing, bytes)")
    if src and src_rep["status"] == "not_looked_up" and _internal(src) is False:
        follow.append(f"lookup_ip ip={src}")
    for d in out_dsts:
        if d["reputation"]["status"] == "not_looked_up":
            follow.append(f"lookup_ip ip={d['dst_ip']}  (the host connected to it after the login)")
    for key, kind, name in (("host_context", "host", host), ("account_context", "account", ents.get("account"))):
        if sources[key]["status"] == "not_queried":
            follow.append(f"get_asset_context {kind}={name}")
    for a, r in searches:
        if r.get("truncated"):
            follow.append(f"search_logs {json.dumps(a)} was truncated ({r['returned']} of {r['total_matched']} "
                          "returned): repeat it with limit=200, or narrow the time window")
    return follow


def _tshark_vs_wazuh(evs, searches, src, host, host_ip, port, success, tshark_ok, attack_start, acct=None) -> dict:
    out = {"status": "not_comparable", "wazuh_attempts": None, "tshark_sessions": None, "difference": None,
           "evidence_refs": [], "explanations": [], "statement": "", "reason": None}
    if not src:
        out["reason"] = "No source IP to compare tshark sessions and Wazuh attempts for."
        return out
    attempts = [e for e in evs if e["source"] == "wazuh" and e["event_type"] in ("auth_failure", "auth_success")
                and e["src_ip"] == src and (not success or e["time"] <= success["time"])
                and (attack_start is None or e["time"] >= attack_start)
                and ((host and _lc(e["host"]) == _lc(host)) or (host_ip and e["dst_ip"] == host_ip))]
    if not attempts:
        out["reason"] = f"No Wazuh login attempts from {src} to compare with tshark sessions."
        return out
    t0, t1 = _t(attempts[0]), _t(attempts[-1])
    w0, w1 = t0 - timedelta(seconds=SESSION_LEAD_S), t1 + timedelta(seconds=SESSION_TRAIL_S)
    if not tshark_ok:
        out["reason"] = "tshark sessions were not available in this run, so they cannot be compared with Wazuh."
        return out
    allowed_t = {"src_ip": {src}, "dst_ip": {host_ip}, "host": {host, host_ip}, "dst_port": {port}}
    allowed_w = {"src_ip": {src}, "dst_ip": {host_ip}, "host": {host, host_ip}}
    if not any(_search_covers(a, r, "tshark", w0, w1, allowed_t, {"network_session"}) for a, r in searches):
        out["reason"] = (f"No successful tshark search covered all sessions from {src} between {attempts[0]['time']} "
                         f"and {attempts[-1]['time']}; session and attempt counts were not compared.")
        return out
    # the Wazuh side must cover the SAME window as the sessions (incl. the lead-in): a search that starts after the
    # first attempts would leave their sessions without attempts and report a false conflict
    sessions = [e for e in evs if e["source"] == "tshark" and e["src_ip"] == src
                and (not host_ip or e["dst_ip"] == host_ip) and e.get("dst_port") == port and w0 <= _t(e) <= w1]
    n_a, n_s = len(attempts), len(sessions)
    kinds = {"auth_failure", "auth_success"}
    if not any(_search_covers(a, r, "wazuh", w0, w1, allowed_w, kinds) for a, r in searches):
        # Without full Wazuh coverage the attempts seen are a LOWER bound (every one is real; more may exist). With the
        # sessions fully covered, that still proves "far too few sessions" (attempts > sessions x MaxAuthTries), and
        # never "consistent".
        if not n_a > n_s * MAX_AUTH_TRIES:
            out["reason"] = (f"No successful Wazuh search covered every login attempt from {src} in the window (e.g. "
                             "the search was limited to one account); counts were not compared.")
            return out
        out.update(status="inconsistent", wazuh_attempts=n_a, tshark_sessions=n_s, difference=n_a - n_s,
                   evidence_refs=_ends(attempts) + _ends(sessions))
        out["statement"] = (f"At least {n_a} Wazuh login attempt(s) from {src} (the Wazuh searches may not show all of "
                            f"them) but only {n_s} tshark "
                            f"SSH session(s) in {attempts[0]['time']} - {attempts[-1]['time']}: inconsistent (more "
                            f"than {MAX_AUTH_TRIES} attempts per session would be needed).")
        out["explanations"] = ["the packet capture missed sessions (capture gap, dropped packets, capture started late)",
                               "sshd allows more attempts per connection than the default MaxAuthTries",
                               "Wazuh events were duplicated or replayed"]
        return out
    consistent = n_s > 0 and n_s <= n_a <= n_s * MAX_AUTH_TRIES
    diff = n_a - n_s
    out.update(status="consistent" if consistent else "inconsistent", wazuh_attempts=n_a, tshark_sessions=n_s,
               difference=diff, evidence_refs=_ends(attempts) + _ends(sessions))
    window = f"{attempts[0]['time']} - {attempts[-1]['time']}"
    if consistent:
        out["statement"] = (f"{n_a} Wazuh login attempt(s) from {src} vs {n_s} tshark SSH session(s) in {window}: "
                            f"consistent (difference {diff}; one SSH connection can carry up to {MAX_AUTH_TRIES} "
                            "password attempts).")
    elif n_s < n_a:
        out["statement"] = (f"{n_a} Wazuh login attempt(s) from {src} but only {n_s} tshark SSH session(s) in {window}: "
                            f"inconsistent ({diff} more attempts than sessions; more than {MAX_AUTH_TRIES} attempts "
                            "per session would be needed).")
        out["explanations"] = ["the packet capture missed sessions (capture gap, dropped packets, capture started late)",
                               "sshd allows more attempts per connection than the default MaxAuthTries",
                               "Wazuh events were duplicated or replayed"]
    else:
        out["statement"] = (f"{n_s} tshark SSH session(s) from {src} but only {n_a} Wazuh login attempt(s) in {window}: "
                            f"inconsistent ({-diff} sessions without a logged attempt).")
        out["explanations"] = ["connections that never reached authentication (scans, banner grabs)",
                               "authentication log events missing from the Wazuh export"]
    return out


def _source_status(failed, src, src_rep, out_dsts, host, host_res, not_found, acct_res, ents, tshark_ok,
                   wazuh_ok) -> dict:
    def failed_search(kind: str) -> list[dict]:
        return [c for c in failed if c["tool"] == "search_logs"
                and (c.get("arguments") or {}).get("source") in (kind, "all")]

    def err(c: dict) -> str:
        res = c.get("result") or {}
        return (res.get("error") if isinstance(res, dict) else None) or c.get("result_summary") or c["status"]

    s: dict[str, dict] = {}
    for key, kind, ok_flag, what in (("auth_logs", "wazuh", wazuh_ok, "login outcomes"),
                                     ("network_sessions", "tshark", tshark_ok, "session counts, timing and bytes")):
        if ok_flag:
            s[key] = {"status": "ok", "detail": f"{KEY_SOURCE_NAMES[key]} searched successfully."}
        elif fs := failed_search(kind):
            s[key] = {"status": "failed", "detail": f"{KEY_SOURCE_NAMES[key]} unavailable: search_logs "
                                                    f"{fs[-1]['status']} ({err(fs[-1])}); {what} unknown."}
        else:
            s[key] = {"status": "not_queried", "detail": f"{KEY_SOURCE_NAMES[key]} were not searched; {what} unknown."}

    unknown_out = [d["dst_ip"] for d in out_dsts if d["reputation"]["status"] != "ok"]
    if src is None:
        s["ip_intel"] = {"status": "not_applicable", "detail": "No source IP in scope."}
    elif src_rep["status"] == "failed":
        c = next(c for c in failed if c["tool"] == "lookup_ip" and (c.get("arguments") or {}).get("ip") == src)
        s["ip_intel"] = {"status": "failed", "detail": f"lookup_ip {src} {c['status']} ({err(c)}): its reputation is "
                                                       "unknown (no data returned)"
                         + (f"; outbound destination(s) {', '.join(unknown_out)} also have unknown reputation."
                            if unknown_out else ".")}
    elif src_rep["status"] == "not_looked_up" and _internal(src):
        s["ip_intel"] = {"status": "not_applicable" if not unknown_out else "partial",
                         "detail": f"{src} is internal; no intel lookup needed"
                                   + (f"; outbound destination(s) {', '.join(unknown_out)} have unknown reputation "
                                      "(not looked up or lookup failed)." if unknown_out else ".")}
    elif src_rep["status"] == "not_looked_up":
        s["ip_intel"] = {"status": "not_queried", "detail": f"lookup_ip was not called for {src}: its reputation is "
                                                            "unknown."}
    elif unknown_out:
        s["ip_intel"] = {"status": "partial", "detail": f"Outbound destination(s) {', '.join(unknown_out)} have unknown "
                                                        "reputation (not looked up or lookup failed)."}
    else:
        s["ip_intel"] = {"status": "ok", "detail": "IP intelligence (MOCK feed) returned for the source IP"
                                                   + (" and every outbound destination." if out_dsts else ".")}

    for key, kind, res, name in (("host_context", "host", host_res, host), ("account_context", "account", acct_res,
                                                                            ents.get("account"))):
        fails = [c for c in failed if c["tool"] == "get_asset_context" and kind in (c.get("arguments") or {})]
        if res:
            s[key] = {"status": "ok", "detail": f"{kind} {name} found in the asset inventory."}
        elif not name:
            s[key] = {"status": "not_applicable", "detail": f"The alert names no {kind}."}
        elif any(_lc(q) in (_lc(name), _lc(ents.get("dst_ip"))) for q in not_found.get(kind, [])):
            s[key] = {"status": "missing", "detail": f"{kind} {name} is not in the asset inventory: "
                                                     + ("criticality, owner and exposure unknown." if kind == "host"
                                                        else "usual source IPs and privileges unknown.")}
        elif fails:
            s[key] = {"status": "failed", "detail": f"get_asset_context {kind} {name} {fails[-1]['status']} "
                                                    f"({err(fails[-1])})."}
        else:
            s[key] = {"status": "not_queried", "detail": f"get_asset_context was not called for {kind} {name}: "
                                                         + ("criticality unknown." if kind == "host"
                                                            else "the account's baseline is unknown.")}
    return s


def _alert_vs_logs(obs, searches, fails, success, acct, host, host_ip, alert_src) -> list[dict]:
    """The alert's own counts vs what the logs show - compared only when a search covered the alert's window."""
    out = []
    want = obs.get("failed_attempts")
    start, end = obs.get("failure_window_start"), obs.get("failure_window_end")
    if isinstance(want, int) and start and end:
        try:
            t0, t1 = parse_utc(start), parse_utc(end)
        except (TypeError, ValueError):
            return out
        if t1.microsecond == 0 and "." not in end:     # a whole-second end covers that whole second
            t1 = t1.replace(microsecond=999999)
        allowed = {"account": {acct}, "host": {host, host_ip}, "src_ip": {alert_src}, "dst_ip": {host_ip}}
        if any(_search_covers(a, r, "wazuh", t0, t1, allowed, {"auth_failure"}) for a, r in searches):
            seen = [e for e in fails if (not alert_src or e["src_ip"] == alert_src) and t0 <= _t(e) <= t1]
            if len(seen) != want:
                out.append({"id": "alert_vs_logs_failures",
                            "statement": f"The alert reports {want} failed attempts between {start} and {end}, but the "
                                         f"logs returned in this run show {len(seen)}.",
                            "evidence_refs": _ends(seen),
                            "possible_explanations": ["the detection counted differently (rule frequency window)",
                                                      "log lines were malformed or missing in the export"]})
    st = obs.get("success_time")
    if st and success:
        try:
            delta = abs((parse_utc(st) - _t(success)).total_seconds())
        except (TypeError, ValueError):
            delta = 0
        if delta > 2:
            out.append({"id": "alert_vs_logs_success_time",
                        "statement": f"The alert's success time {st} differs from the logged success {success['time']} "
                                     f"by {delta:.0f} s.", "evidence_refs": [success["evidence_ref"]],
                        "possible_explanations": ["clock skew between sources", "a different login was meant"]})
    return out


def condense_timeline(timeline: list[dict]) -> list[dict]:
    """The timeline for the model: entries with the same phase, source, event type, account and addresses are
    merged into one row with count, first/last time and their first/last refs (every merged ref is still in
    the full timeline stored in the assessment). Ordered by first time."""
    groups: dict[tuple, list[dict]] = {}
    for e in timeline:
        key = (e["phase"], e["source"], e["event_type"], e["account"], e["src_ip"], e["dst_ip"])
        groups.setdefault(key, []).append(e)
    out = []
    for evs in groups.values():
        first = evs[0]
        row = {k: first[k] for k in ("time", "phase", "source", "event_type", "account", "host", "src_ip", "dst_ip")}
        row.update(count=len(evs), last_time=evs[-1]["time"],
                   summary=first["summary"] if len(evs) == 1 else f"{len(evs)} x: {first['summary'][:110]}",
                   evidence_refs=_ends(evs))
        out.append(row)
    return sorted(out, key=lambda r: (r["time"], r["source"]))


def model_view(correlation: dict) -> dict:
    """What correlate_evidence returns to the model: the correlation with a condensed timeline; coverage
    problems first (a live model submitted findings without acting on follow-ups listed further down)."""
    fu = correlation["suggested_follow_ups"]
    view = {"next_step": (f"Before submit_findings, make these {len(fu)} follow-up call(s), then call "
                          "correlate_evidence again: " + " | ".join(fu)) if fu else
            "Coverage complete: no follow-up calls suggested. If gaps remain below, they cannot be closed with "
            "the tools; state them in unknowns.",
            "suggested_follow_ups": fu, "gaps": correlation["gaps"], "conflicts": correlation["conflicts"]}
    view.update({k: v for k, v in correlation.items() if k not in view and k != "timeline"})
    view["timeline"] = condense_timeline(correlation["timeline"])
    view["timeline_note"] = (f"{len(correlation['timeline'])} timeline events condensed into {len(view['timeline'])} "
                             "rows (same phase/source/type/account/addresses); cite the first/last refs shown.")
    return view
