"""Assessment-phase tools (Day 3): correlate_evidence (read) and submit_findings (write_internal).

correlate_evidence() takes no arguments. It runs the deterministic correlation (correlate.py) on
the tool results of THIS run only and returns facts, a condensed timeline, gaps and conflicts,
each with evidence refs. The agent decides when to call it; the computation is not the model's.

submit_findings(...) is the only way the agent's assessment counts. Besides the full schema
(schemas/findings.schema.json, applied by the wrapper), the handler checks the findings against
the run (problems are returned exactly, at most MAX_FINDINGS_ATTEMPTS submissions):
  - every evidence_ref was returned by a tool in this run; every claim cites at least one ref
    (anything that cannot be cited belongs in unknowns)
  - hypotheses: exactly the plan's hypothesis ids; supported / refuted cite evidence
  - MITRE: id in the local catalog (data/mitre_catalog.json), matching name, cited refs include
    an event of the kind the technique needs (e.g. T1078 needs a successful login)
  - correlation gaps (failed / missing / timed-out sources) -> unknowns must not be empty and
    confidence cannot be high; unresolved conflicts -> confidence cannot be high
  - IP reputation claims cite the lookup_ip ref and say it is MOCK intel; reputation that could
    not be looked up (lookup_ip failed) can only be stated in unknowns
  - containment recommendations need requires_approval: true (nothing is executed)
  - severity is compared with the rubric (severity.py). A different severity is never overwritten:
    the rationale must address the rubric explicitly; the first time it does not, the submission
    is rejected with the rubric's factors as a hint; after that it is accepted and the
    disagreement is recorded ({agent_severity, rubric_severity, agrees, ...}).
"""
from __future__ import annotations

import json
import re
from functools import lru_cache

from soc_agent.config import PROJECT_ROOT
from soc_agent.correlate import BRUTE_FORCE_MIN, correlate, model_view
from soc_agent.correlate import _internal as _internal_ip
from soc_agent.schemas import load_schema, load_tool_schema
from soc_agent.severity import CONFIDENCES, SEVERITIES, rubric  # noqa: F401  (SEVERITIES: level order)
from soc_agent.tools.base import RunContext, ToolRejection, ToolSpec

MAX_FINDINGS_ATTEMPTS = 5      # content checks; findings are 16 fields / 30+ claims (a live model needed 4 once)
MAX_FORMAT_REJECTIONS = 5      # separate budget for schema (format) rejections, so they do not use up the 5
MAX_SEVERITY_DEVIATION = 1     # levels an agent severity may differ from the rubric (with a rationale)
MITRE_CATALOG = PROJECT_ROOT / "data" / "mitre_catalog.json"
ANSWER_KEYS = ("account_and_asset", "timeline", "source_ip_intelligence", "related_events", "severity_justification",
               "containment")
QUESTIONS = {
    "account_and_asset": "a. Which account and asset are involved?",
    "timeline": "b. What is the timeline, and which events support the alert?",
    "source_ip_intelligence": "c. What does approved intelligence say about the source IP?",
    "related_events": "d. Are there related events before or after the successful login / key event?",
    "severity_justification": "e. What severity is justified by evidence? (What is still unknown: see unknowns.)",
    "containment": "f. What containment or remediation should a human analyst consider?",
}
SEVERITY_HINT_MARK = "differs from the rubric"
# a live model kept omitting this field or sending it as a string: it confuses it with severity_rationale
SEVERITY_JUSTIFICATION_NOTE = (
    "severity_justification is the ANSWER to question e and is NOT severity_rationale: severity_rationale is one "
    "string, severity_justification is a JSON ARRAY of claim objects, e.g. [{\"statement\": \"Severity high: 50 "
    "failures then a success from an external IP outside the baseline\", \"evidence_refs\": "
    "[\"wazuh_alerts.jsonl#L56\"]}]. Send both.")
HYPOTHESIS_HINT_MARK = "contradicts the deterministic facts"
_REP_WORDS = re.compile(r"\b(reputation|threat[- ]?intel\w*|intel(?:ligence)?|intel feed)\b", re.I)
_REP_VERDICT = re.compile(r"\b(malicious|suspicious|benign|clean|known[- ]bad|blocklist\w*|c2|command[- ]and[- ]control|"
                          r"botnet|bad reputation)\b", re.I)
_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_PLACEHOLDER = re.compile(r"^\W*(none|n/?a|nothing|no unknowns?|unknown|tbd|-+)\W*$", re.I)


@lru_cache(maxsize=1)
def mitre_catalog() -> dict:
    return json.loads(MITRE_CATALOG.read_text(encoding="utf-8"))["techniques"]


# ------------------------------------------------------------------ correlate_evidence
def run_correlation(ctx: RunContext) -> dict:
    """The full correlation of this run so far (deterministic)."""
    return correlate(ctx.alert, ctx.evidence_results, ctx.tool_calls)


def _correlate_evidence(args: dict, ctx: RunContext) -> dict:
    return model_view(run_correlation(ctx))


def _summarize_correlation(r: dict) -> str:
    s = r["signals"]
    return (f"{r['evidence_basis']['timeline_events']} timeline events, {len(r['facts'])} facts, {len(r['gaps'])} gap(s), "
            f"{len(r['conflicts'])} conflict(s); success_after_failures={s['success_after_failures']}")


CORRELATE_EVIDENCE = ToolSpec(
    name="correlate_evidence",
    description=("Correlate the evidence gathered so far IN THIS RUN (no arguments). Deterministic, no guessing: "
                 "returns a phase-labelled timeline (baseline / attack / compromise / post_compromise), facts with "
                 "evidence_refs (failures per account and source IP, success after failures, baseline check, other "
                 "accounts targeted, post-login sudo / account changes / outbound connections, tshark vs Wazuh "
                 "counts), gaps (missing, failed or timed-out sources) and conflicts. Call it after gathering "
                 "evidence and before submit_findings; call it again after follow-up tool calls."),
    parameters=load_tool_schema("correlate_evidence", "input"),
    handler=_correlate_evidence,
    permission="read",
    output_schema=load_tool_schema("correlate_evidence", "output"),
    summarize=_summarize_correlation,
    evidence_source=False,           # derived from other results; its refs were already returned by evidence tools
)


# ---------------------------------------------------------------------- submit_findings
def _ref_events(ctx: RunContext) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in ctx.evidence_results:
        if r["tool"] == "search_logs":
            for e in r["result"].get("events", []):
                out.setdefault(e["evidence_ref"], e)
    return out


def _failed_lookup_ips(ctx: RunContext) -> set[str]:
    ok = {(r.get("arguments") or {}).get("ip") for r in ctx.evidence_results if r["tool"] == "lookup_ip"}
    return {(c.get("arguments") or {}).get("ip") for c in ctx.tool_calls
            if c["tool"] == "lookup_ip" and c["status"] in ("timeout", "error")} - ok - {None}


def _verdict_about(ip: str, text: str) -> bool:
    """A reputation verdict stated about this IP without saying "intel", e.g. "203.0.113.77 is a known
    malicious scanner", "198.51.100.23, a known C2 server" or "the malicious source 203.0.113.77"."""
    v, ipre = _REP_VERDICT.pattern, rf"(?<![\d.]){re.escape(ip)}(?!\.?\d)"
    link = r"(?:is|was|as|classified|listed|flagged|rated|a|an|known|likely|probably|confirmed|the|be|been|seems)"
    return bool(re.search(rf"{ipre}\W+(?:{link}\W+){{1,4}}{v}", text, re.I)
                or re.search(rf"{v}\W+(?:\w+\W+)?(?:ip|address|source|host|destination|server|scanner)\W+(?:ip\W+)?"
                             rf"{ipre}", text, re.I))


def _reputation_problems(where: str, text: str, refs: list[str] | None, ctx: RunContext, known: set[str],
                         failed_ips: set[str], refs_field: str = "this claim's evidence_refs") -> list[str]:
    """Reputation statements must rest on this run's lookup_ip results and say MOCK. refs=None marks free text
    without refs (rationales, alternative explanations, next steps): there a known IP's reputation needs the
    word MOCK, and a verdict about an IP without (successful) intel in this run is refused. refs_field names
    where the refs of this text live, so the problem says exactly which field to change (a live model kept
    rewriting severity_rationale when the missing ref belonged in severity_evidence_refs)."""
    issues = []
    free = refs is None
    refs = refs or []
    rep_refs = [r for r in refs if ctx.evidence_refs.get(r) == "lookup_ip"]
    if rep_refs and "mock" not in text.lower():
        issues.append(f"{where}: cites IP intelligence ({rep_refs[0]}) but does not say it is MOCK intel: add the "
                      f"words 'MOCK intel' to this text, or remove {rep_refs[0]} from {refs_field} if it does "
                      "not rest on intelligence")
    rep_words = _REP_WORDS.search(text) is not None
    for ip in sorted(set(_IP.findall(text))):
        verdict = _verdict_about(ip, text)
        if ip in failed_ips:
            if verdict or (rep_words and not free):
                issues.append(f"{where}: talks about the reputation of {ip}, but lookup_ip for {ip} failed or timed "
                              "out in this run (no data). State this in unknowns, not as a claim")
        elif ip in known:
            if (verdict or rep_words) and (f"ip_reputation.json#{ip}" not in refs if not free
                                           else "mock" not in text.lower()):
                issues.append(f"{where}: talks about the reputation of {ip} but "
                              + ("does not say it is MOCK intel" if free else
                                 f"does not cite ip_reputation.json#{ip}: add \"ip_reputation.json#{ip}\" to "
                                 f"{refs_field} (writing it in the text is not citing), or remove the reputation "
                                 "statement"))
        elif verdict:
            issues.append(f"{where}: states a reputation verdict about {ip}, but lookup_ip returned no intelligence "
                          f"for {ip} in this run; look it up first, or state it as unknown")
    if (rep_words and _REP_VERDICT.search(text) and not any(p.startswith(where) for p in issues)
            and (not rep_refs if not free else "mock" not in text.lower())):
        issues.append(f"{where}: states an intelligence verdict without "
                      + ("saying it is MOCK intel" if free else
                         f"citing a lookup_ip ref: add the matching ref ("
                         + (", ".join(f'"ip_reputation.json#{i}"' for i in sorted(known)) or "none was returned")
                         + f") to {refs_field} and say MOCK intel, or remove the verdict"))
    return issues


# a containment action labelled "investigative" would skip the approval requirement
_CONTAINMENT = re.compile(
    r"\b(block|blocklist|disable|isolate|quarantine|shut\s*down|revoke|lock\s+(?:out|the\s+account)|terminate|kill|"
    r"delete|deny|firewall|null-?route|sinkhole|ban|suspend|disconnect|expire|rotate|log\s*(?:out|off)|logout|"
    r"reset\s+(?:the\s+)?(?:\S+'s\s+)?password|force\s+(?:a\s+)?password|take\b.{0,40}?\boffline|"
    r"remove\s+(?:\S+\s+){0,3}?(?:account|user))", re.I)


def findings_problems(f: dict, ctx: RunContext, correlation: dict, rub: dict) -> tuple[list[str], dict]:
    """Run-level checks (the wrapper has applied the full schema). Returns (problems, severity_check)."""
    issues: list[str] = []
    known_rep_ips = {r.split("#", 1)[1] for r, tool in ctx.evidence_refs.items() if tool == "lookup_ip"}
    failed_ips = _failed_lookup_ips(ctx)

    def check_refs(where: str, refs: list[str], need: bool, empty_hint: str) -> None:
        if need and not refs:
            issues.append(f"{where}: {empty_hint}")
        for ref in refs:
            if ref not in ctx.evidence_refs:
                issues.append(f"{where}: evidence_ref {ref!r} was not returned by any tool in this run"
                              + _no_intel_hint(ref, correlation))

    for key in ANSWER_KEYS:
        for i, c in enumerate(f[key], 1):
            where = f"{key} claim {i}"
            check_refs(where, c["evidence_refs"], True,
                       "claim has no evidence_refs; cite the refs it rests on, or move the statement to unknowns")
            issues += _reputation_problems(where, c["statement"], c["evidence_refs"], ctx, known_rep_ips, failed_ips)

    check_refs("severity_evidence_refs", f["severity_evidence_refs"], True,
               "cite at least one evidence_ref that justifies the severity")
    issues += _reputation_problems("severity_rationale", f["severity_rationale"], f["severity_evidence_refs"], ctx,
                                   known_rep_ips, failed_ips, refs_field="severity_evidence_refs")

    plan_ids = [h.get("id") for h in (ctx.plan or {}).get("hypotheses", []) if isinstance(h, dict)]
    got = [h["id"] for h in f["hypotheses"]]
    for hid in sorted({x for x in got if got.count(x) > 1}):
        issues.append(f"hypotheses: {hid} appears more than once")
    if plan_ids:
        if missing := [h for h in plan_ids if h not in got]:
            issues.append(f"hypotheses: missing plan hypothesis id(s) {missing}; give a status for every one of "
                          f"{plan_ids}")
        if extra := [h for h in got if h not in plan_ids]:
            issues.append(f"hypotheses: {extra} are not hypotheses of the plan (plan ids: {plan_ids})")
    for h in f["hypotheses"]:
        where = f"hypothesis {h['id']}"
        check_refs(where, h["evidence_refs"], h["status"] != "undetermined",
                   f"status {h['status']} needs at least one evidence_ref")
        issues += _reputation_problems(f"{where} reasoning", h["reasoning"], h["evidence_refs"], ctx, known_rep_ips,
                                       failed_ips, refs_field=f"the evidence_refs of hypothesis {h['id']}")
    challenges = _hypothesis_challenges(f, ctx, correlation, rub, issues)

    catalog, events = mitre_catalog(), _ref_events(ctx)
    for m in f["mitre"]:
        tid, where = m["technique_id"], f"mitre {m['technique_id']}"
        entry = catalog.get(tid)
        if entry is None:
            issues.append(f"{where}: not in the local MITRE catalog; use one of {', '.join(sorted(catalog))}")
            continue
        names = {entry["name"].lower(), entry["name"].split(": ", 1)[-1].lower()}
        if m["name"].strip().lower() not in names:
            issues.append(f"{where}: name should be {entry['name']!r}, not {m['name']!r}")
        check_refs(where, m["evidence_refs"], True, "cite the events that justify this technique")
        cited = [events[r] for r in m["evidence_refs"] if r in events]
        need = entry.get("requires_event_types") or []
        if m["evidence_refs"] and need and not any(e["event_type"] in need for e in cited):
            issues.append(f"{where}: none of the cited refs is a {' / '.join(need)} event; {entry['name']} is only "
                          "justified by such evidence (cite it, or drop the technique)")
        if (n := entry.get("requires_distinct_accounts")) and len({e["account"] for e in cited
                                                                    if e["event_type"] in need}) < n:
            issues.append(f"{where}: cite failed logins for at least {n} different accounts (password spraying "
                          "means one source trying several accounts)")
        issues += _reputation_problems(f"{where} justification", m["justification"], m["evidence_refs"], ctx,
                                       known_rep_ips, failed_ips, refs_field=f"the evidence_refs of {tid}")
        sig = correlation["signals"]
        n_fail = max(sig["failures_for_account"], sig["failures_from_source"])
        if entry.get("brute_force") and n_fail < BRUTE_FORCE_MIN:
            issues.append(f"{where}: {entry['name']} needs at least {BRUTE_FORCE_MIN} failed logins (the brute-force "
                          f"threshold, docs/severity.md); this run shows {n_fail}. Drop the technique")
        if entry.get("requires_internal_source"):
            logins = [e for e in cited if e["event_type"] == "auth_success"]
            ext = sorted({e["src_ip"] for e in logins if e["src_ip"] and _internal_ip(e["src_ip"]) is False})
            if logins and ext and len(ext) == len({e["src_ip"] for e in logins if e["src_ip"]}):
                issues.append(f"{where}: {entry['name']} is lateral movement between internal hosts, but the cited "
                              f"login came from the external address {', '.join(ext)}. A login with valid credentials "
                              "from outside is T1078 Valid Accounts (T1133 External Remote Services for an "
                              "internet-facing service); use that instead")
        if entry.get("adversary_login"):
            base = set(sig.get("baseline_ips") or [])
            logins = [e for e in cited if e["event_type"] == "auth_success"]
            if base and logins and all(e["src_ip"] in base for e in logins):
                issues.append(f"{where}: the cited login(s) came from {', '.join(sorted({e['src_ip'] for e in logins}))}"
                              ", which is in the account's baseline (usual IPs / earlier logins): that is not evidence "
                              "of adversary use. Drop the technique, or cite a login from outside the baseline")

    for where, text in ([("confidence_rationale", f["confidence_rationale"])]
                        + [(f"alternative_explanations {i}", x) for i, x in enumerate(f["alternative_explanations"], 1)]
                        + [(f"recommended_next_steps {i}", st["action"] + " " + st["rationale"])
                           for i, st in enumerate(f["recommended_next_steps"], 1)]):
        issues += _reputation_problems(where, text, None, ctx, known_rep_ips, failed_ips)

    gaps, conflicts = correlation["gaps"], correlation["conflicts"]
    real_unknowns = [u for u in f["unknowns"] if not _PLACEHOLDER.match(u)]
    if len(real_unknowns) < len(f["unknowns"]):
        issues.append("unknowns: remove placeholder entries such as 'None.'; list what is actually unknown")
    if gaps and not real_unknowns:
        issues.append("unknowns: must not be empty - the correlation found gaps: "
                      + "; ".join(g["statement"] for g in gaps[:4]))
    if f["confidence"] == "high" and (gaps or conflicts):
        why = [g["statement"] for g in gaps[:3]] + [c["statement"] for c in conflicts[:2]]
        issues.append("confidence: cannot be high while evidence is missing, failed, timed out or conflicting: "
                      + "; ".join(why))
    for i, s in enumerate(f["recommended_next_steps"], 1):
        if s["type"] == "containment" and s["requires_approval"] is not True:
            issues.append(f"recommended_next_steps {i}: containment is only a recommendation for analyst "
                          "consideration and needs requires_approval: true (nothing is executed)")
        elif s["type"] == "investigative" and (m := _CONTAINMENT.search(s["action"])):
            issues.append(f"recommended_next_steps {i}: {m.group(0)!r} is a containment action; set type "
                          "containment and requires_approval: true (for analyst consideration; nothing is executed)")

    sev = rub["severity"]
    agrees = f["severity"] == sev["severity"]
    # addressing the rubric = naming it and its level, e.g. "the rubric says critical, but ..."
    addresses = ("rubric" in f["severity_rationale"].lower()
                 and re.search(rf"\b{sev['severity']}\b", f["severity_rationale"], re.I) is not None)
    earlier_hint = any(c["tool"] == SUBMIT_FINDINGS.name and c["status"] == "rejected"
                       and SEVERITY_HINT_MARK in json.dumps(c.get("result"), default=str) for c in ctx.tool_calls)
    gap = abs(SEVERITIES.index(f["severity"]) - SEVERITIES.index(sev["severity"]))
    if gap > MAX_SEVERITY_DEVIATION:
        issues.append(f"severity: {f['severity']} is {gap} levels from the rubric ({sev['severity']}, rule {sev['rule']}). "
                      f"An analyst may deviate by at most {MAX_SEVERITY_DEVIATION} level with a rationale; "
                      f"{_level_conditions(f['severity'], correlation)} Choose a severity within one level of "
                      f"{sev['severity']} and explain it")
    elif not agrees and not addresses and not earlier_hint:
        factors = "; ".join(f"{x['factor']} [{x['effect']}]" for x in sev["factors"])
        issues.append(f"severity: {f['severity']} {SEVERITY_HINT_MARK} ({sev['severity']}, rule {sev['rule']}). "
                      "Keep your severity if the evidence justifies it, but severity_rationale must address the "
                      f"difference: mention the rubric and its level ({sev['severity']}) and cite the evidence. "
                      f"Rubric factors: {factors}")
    check = {
        "agent_severity": f["severity"], "rubric_severity": sev["severity"], "agrees": agrees,
        "rubric_rule": sev["rule"], "rubric_score": sev["score"],
        "rationale_addresses_rubric": addresses if not agrees else None,
        "accepted_after_rubric_hint": (not agrees and not addresses and earlier_hint) or None,
        "agent_confidence": f["confidence"], "rubric_confidence": rub["confidence"]["confidence"],
        "confidence_agrees": f["confidence"] == rub["confidence"]["confidence"],
        "hypothesis_challenges": challenges,
    }
    return issues, check


def _hypothesis_challenges(f: dict, ctx: RunContext, correlation: dict, rub: dict, issues: list[str]) -> list[dict]:
    """A benign hypothesis whose status contradicts the deterministic facts is challenged ONCE, like a severity
    disagreement: refuted although the rubric's benign rule (L2) holds, or supported although the rubric rates
    the alert high/critical. The agent may keep its status if its reasoning addresses the facts; it is then
    accepted and recorded, never overwritten."""
    rule, level = rub["severity"]["rule"], rub["severity"]["severity"]
    sig = correlation["signals"]
    benign_ids = {h.get("id") for h in (ctx.plan or {}).get("hypotheses", []) if isinstance(h, dict) and h.get("benign")}
    earlier = any(c["tool"] == SUBMIT_FINDINGS.name and c["status"] == "rejected"
                  and HYPOTHESIS_HINT_MARK in json.dumps(c.get("result"), default=str) for c in ctx.tool_calls)
    out = []
    for h in f["hypotheses"]:
        if h["id"] not in benign_ids:
            continue
        if h["status"] == "refuted" and rule.startswith("L2"):
            facts = (f"source {sig['source_ip']} is in the account's baseline, {sig['failures_for_account']} failure(s) "
                     f"(< {BRUTE_FORCE_MIN}), no other accounts targeted, nothing suspicious after the login")
            addressed = "baseline" in h["reasoning"].lower()
        elif h["status"] == "supported" and level in ("high", "critical"):
            facts = f"the rubric rates the evidence {level} ({rule})"
            addressed = "rubric" in h["reasoning"].lower() or level in h["reasoning"].lower()
        else:
            continue
        out.append({"id": h["id"], "status": h["status"], "rubric_rule": rule[:3].rstrip(":"), "addressed": addressed,
                    "accepted_after_hint": (not addressed and earlier) or None})
        if not addressed and not earlier:
            issues.append(f"hypothesis {h['id']} (benign): {h['status']} {HYPOTHESIS_HINT_MARK}: {facts}. Keep your "
                          "status only if the evidence justifies it; then the reasoning must address these facts "
                          "(e.g. mention the baseline) and cite them")
    return out


def _submit_findings(args: dict, ctx: RunContext) -> dict:
    if ctx.findings is not None:
        raise ToolRejection("Findings were already accepted for this investigation. Do not submit again.")
    attempts = 1 + _content_attempts(ctx)
    if attempts > MAX_FINDINGS_ATTEMPTS:
        raise ToolRejection(f"Too many findings submissions (limit {MAX_FINDINGS_ATTEMPTS}). Stop and report failure.")
    correlation = run_correlation(ctx)
    rub = rubric(correlation)
    issues, check = findings_problems(args, ctx, correlation, rub)
    if issues:
        # problems start with the field they concern ("hypothesis H2: ..." concerns the field hypotheses)
        fields = {"hypotheses" if (f := re.split(r"[ :]", p, maxsplit=1)[0]) == "hypothesis" else f for p in issues}
        if fields & {"severity_rationale", "severity_evidence_refs"}:      # the rationale's refs live in the other
            fields |= {"severity_rationale", "severity_evidence_refs"}
        fields = sorted(fields)
        ctx.findings_flawed_fields = [x for x in fields if x in load_schema("findings")["properties"]]
        raise ToolRejection("Findings rejected.", issues,
                            f"Fix exactly these problems and call submit_findings again with the COMPLETE findings: "
                            f"all 16 fields. Only these fields need changes: {', '.join(fields)}; keep every other "
                            f"field exactly as you sent it (attempt {attempts} of {MAX_FINDINGS_ATTEMPTS}). "
                            "Cite only evidence_ref strings exactly as tools returned them.")
    ctx.findings = args
    ctx.findings_check = {"correlation": correlation, "rubric": rub, "severity_check": check}
    note = "" if check["agrees"] else f" Your severity differs from the rubric ({check['rubric_severity']}); recorded."
    return {"accepted": True, "message": "Findings stored." + note + " Reply with one short sentence.",
            "severity_check": check}


def _no_intel_hint(ref: str, correlation: dict) -> str:
    """For ip_reputation.json#<ip> when lookup_ip found no record (e.g. an internal address): what to cite instead."""
    if not ref.startswith("ip_reputation.json#"):
        return ""
    facts = {f["id"]: f for f in correlation["facts"]}
    alt = [r for fid in ("source_ip_type", "source_ip_baseline") for r in facts.get(fid, {}).get("evidence_refs", [])]
    return (f" (lookup_ip found no intel record for {ref.split('#', 1)[1]}, so there is no ip_reputation ref to cite; "
            "for the source IP cite the refs of the facts source_ip_type / source_ip_baseline"
            + (f": {', '.join(dict.fromkeys(alt))}" if alt else "") + ")")


def _refuse_fact_ids(args: dict, ctx: RunContext) -> None:
    """A correlate_evidence fact id (e.g. "source_ip_baseline") sent as an evidence_ref: name the fact's real refs
    (a live model did this three times in a row). Counted as a format rejection."""
    facts = {f["id"]: f["evidence_refs"] for f in run_correlation(ctx)["facts"]}
    found = []

    def walk(v, path):
        if isinstance(v, dict):
            for k, x in v.items():
                if k in ("evidence_refs", "severity_evidence_refs") and isinstance(x, list):
                    found.extend((f"{path}{k}", r) for r in x if isinstance(r, str) and r in facts)
                else:
                    walk(x, f"{path}{k}/")
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, f"{path}{i}/")
    walk(args, "")
    if found:
        raise ToolRejection("Invalid arguments for submit_findings.", [
            f"{path}: {fid!r} is the id of a correlate_evidence fact, not an evidence_ref; cite that fact's "
            f"evidence_refs instead: {', '.join(facts[fid]) or '(it has none: drop it)'}" for path, fid in found][:8],
            hint="evidence_refs are strings such as wazuh_alerts.jsonl#L64 exactly as tools returned them.")


def _content_attempts(ctx: RunContext) -> int:
    """Earlier submissions that reached the content checks (accepted, or rejected by them, or over the limit)."""
    return sum(1 for c in ctx.tool_calls if c["tool"] == SUBMIT_FINDINGS.name
               and not _format_rejected(c))


def _format_rejected(call: dict) -> bool:
    res = call.get("result") if isinstance(call.get("result"), dict) else {}
    return call["status"] == "rejected" and str(res.get("error", "")).startswith("Invalid arguments")


def _level_conditions(level: str, correlation: dict) -> str:
    """What the rubric needs for `level`, and the facts of this run that contradict it."""
    s = correlation["signals"]
    if level in ("high", "critical"):
        need = ("high and critical need a successful login after the failures (rules C1, C2, H1, H2)"
                + (" plus sudo / a new account on a high-criticality host, or a suspicious outbound connection"
                   if level == "critical" else ""))
        facts = []
        if s["success_after_failures"] is not True:
            facts.append("no successful login after the failures was found (fact success_after_failures)"
                         if s["success_after_failures"] is False else "the login outcome is unknown")
        if level == "critical" and not (s["post_privileged_actions"] or s["post_account_changes"]
                                        or any(d["classification"] in ("malicious", "suspicious")
                                               for d in s["post_outbound_external"])):
            facts.append("no sudo, account change or suspicious outbound connection after the login was found")
        return need + ("; in this run " + "; ".join(facts) + "." if facts else ".")
    return ("low and medium are for failures without a success, a known/internal source or missing evidence; "
            "the rubric's factors in this run point higher.")


def _justification_note(args: dict) -> list[str]:
    sj = args.get("severity_justification")
    mixed_up = sj is None or isinstance(sj, str) or (isinstance(sj, list) and any(isinstance(x, str) for x in sj))
    return [SEVERITY_JUSTIFICATION_NOTE] if mixed_up else []


def _carry_over(args: dict, ctx: RunContext) -> tuple[dict, list[str]]:
    """A resubmission that leaves out required fields gets them from the model's own previous submission in
    this run (a live model regenerating ~9 KB of findings kept dropping one field). The merged findings then
    get the FULL schema and every check; nothing is filled in by the application."""
    _refuse_fact_ids(args, ctx)
    if ctx.findings is None:
        fmt = sum(1 for c in ctx.tool_calls if c["tool"] == SUBMIT_FINDINGS.name and _format_rejected(c))
        if fmt >= MAX_FORMAT_REJECTIONS or _content_attempts(ctx) >= MAX_FINDINGS_ATTEMPTS:
            raise ToolRejection(f"Too many findings submissions (limits: {MAX_FINDINGS_ATTEMPTS} checked, "
                                f"{MAX_FORMAT_REJECTIONS} with format errors). Stop and report failure.")
    required = load_schema("findings")["required"]
    prev = ctx.findings_draft
    missing = [k for k in required if k not in args]
    if ctx.findings is not None or not prev or not missing:
        ctx.findings_draft = dict(args)
        return args, _justification_note(args)
    # a field the previous attempt got WRONG is never carried over (that would repeat its problems forever, as a
    # live run did): leaving it out then fails the schema with "'<field>' is a required property" and this note
    flawed = set(ctx.findings_flawed_fields)
    carried = [k for k in missing if k in prev and k not in flawed]
    refused = [k for k in missing if k in flawed]
    merged = {**args, **{k: prev[k] for k in carried}}
    ctx.findings_draft = merged
    notes = []
    if carried:
        notes.append(f"Fields missing from this submission were taken from your previous submission: "
                     f"{', '.join(carried)}.")
    if refused:
        notes.append(f"Not taken from your previous submission because they had problems: {', '.join(refused)}. "
                     "Send them, fixed.")
    return merged, notes + _justification_note(args)


def _findings_argument_schema() -> dict:
    # Like the plan and the evidence log, the findings ARE the arguments (top-level fields, no nested
    # {"findings": {...}}): live models send one big nested object argument as a malformed string.
    return {k: v for k, v in load_schema("findings").items() if k not in ("$id", "title")}


SUBMIT_FINDINGS = ToolSpec(
    name="submit_findings",
    description=("Submit the initial assessment (exactly once, after correlate_evidence). Arguments: the six answers "
                 "(account_and_asset, timeline, source_ip_intelligence, related_events, severity_justification, "
                 "containment) as JSON arrays of {statement, evidence_refs}; hypotheses [{id, status "
                 "supported|refuted|undetermined, reasoning, evidence_refs}] for every plan hypothesis; severity "
                 "low|medium|high|critical + severity_rationale + severity_evidence_refs; confidence low|medium|high + "
                 "confidence_rationale; mitre [{technique_id, name, justification, evidence_refs}] only where "
                 "justified; unknowns; alternative_explanations; recommended_next_steps [{action, type "
                 "investigative|containment, rationale, requires_approval}]. Every claim cites refs returned in this "
                 "run. If problems are returned, fix exactly those and resubmit (5 attempts in total)."),
    parameters=_findings_argument_schema(),
    prepare=_carry_over,
    field_hints={
        "containment": "containment is required even when nothing needs containing; then send one claim such as "
                       "{\"statement\": \"No containment is indicated: <why, e.g. the login came from the account's "
                       "usual IP>\", \"evidence_refs\": [<the refs that show it>]}",
        "hypotheses": "list every plan hypothesis id with status supported | refuted | undetermined, reasoning and "
                      "evidence_refs",
        "unknowns": "list what is still unknown (failed or missing sources, open questions); it is never empty when "
                    "the correlation reports gaps",
        "mitre": "send [] when no technique is justified by the cited events",
        "alternative_explanations": "send the alternative explanations you considered (strings), or []",
    },
    retry_hint=("Call submit_findings again with the COMPLETE findings: all 16 fields (the six answers, hypotheses, "
                "severity, severity_rationale, severity_evidence_refs, confidence, confidence_rationale, mitre, "
                "unknowns, alternative_explanations, recommended_next_steps), not only the corrected ones."),
    handler=_submit_findings,
    permission="write_internal",
    output_schema=load_tool_schema("submit_findings", "output"),
    summarize=lambda r: (f"findings accepted; severity {r['severity_check']['agent_severity']} (rubric "
                         f"{r['severity_check']['rubric_severity']}), confidence {r['severity_check']['agent_confidence']}"),
)

ASSESSMENT_TOOLS = [CORRELATE_EVIDENCE, SUBMIT_FINDINGS]
assert set(SEVERITIES) == set(load_schema("findings")["properties"]["severity"]["enum"])
assert set(CONFIDENCES) == set(load_schema("findings")["properties"]["confidence"]["enum"])
