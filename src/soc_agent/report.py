"""Day 4 incident report: built by CODE from the database, validated, rendered to Markdown, versioned.

build_report(store, investigation_id) reads only what the database holds for the investigation:
  - the accepted assessment (phase "assess": findings, rubric, timeline, facts, gaps, conflicts)
  - the agent's report content (phase "report": executive summary + recommendations accepted by
    submit_report_content) - the ONLY text the agent writes for the report
  - pending actions, analyst decisions and simulated executions (approval status per recommendation)
  - the evidence index (ref -> excerpt of the tool result) for the evidence appendix
No field is invented by an LLM at build time. The JSON is validated against schemas/incident_report.schema.json
before it is stored (reports table, one row per version) and written to reports/<id>.v<N>.{json,md}.
refresh_report() rebuilds after an analyst decision / execution / close and stores a new version only if
something changed.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from soc_agent import __version__
from soc_agent.schemas import SchemaError, load_schema, problems
from soc_agent.store import CLOSED, Store, StoreError, now, parse_time
from soc_agent.tools.actions import ACTION_WORDS as _ACTION_WORDS

QUESTIONS = {
    "account_and_asset": "Which account and asset are involved?",
    "timeline": "What is the timeline, and which events support the alert?",
    "source_ip_intelligence": "What does approved intelligence say about the source IP?",
    "related_events": "Are there related events before or after the successful login?",
    "severity_justification": "What severity is justified by evidence?",
    "containment": "What containment or remediation should a human analyst consider?",
}
ROLE_BY_EVENT = {"auth_failure": "failed logins", "auth_success": "successful login / session",
                 "privilege": "privilege use (sudo)", "account_change": "account created / changed",
                 "network_session": "network session", "other": "other log event"}
SYNTHETIC_BANNER = "SYNTHETIC LAB DATA - MOCK INTELLIGENCE"
MOCK_LLM_BANNER = "[MOCK LLM]"


class ReportError(RuntimeError):
    pass


def _refs(value) -> list[str]:
    from soc_agent.tools.base import collect_refs
    return collect_refs(value)


def _internal(ip: str | None) -> bool | None:
    from soc_agent.correlate import _internal as internal
    return internal(ip)


def _event_text(e: dict) -> str:
    who = f"{e['account']} " if e.get("account") else ""
    route = f"{e.get('src_ip') or '?'} -> {e.get('dst_ip') or '?'}"
    return f"{e['event_type']} {who}{route}" + (f" on {e['host']}" if e.get("host") else "")


def _entities(alert: dict, a: dict, evidence: dict) -> dict:
    ents, facts = alert.get("entities") or {}, {f["id"]: f for f in a["facts"]}
    accounts: dict[str, dict] = {}
    hosts: dict[str, dict] = {}
    ips: dict[str, dict] = {}

    def acc(name, role, refs=()):
        r = accounts.setdefault(name.lower(), {"name": name, "roles": [], "inventory_role": None, "evidence_refs": []})
        if role not in r["roles"]:
            r["roles"].append(role)
        r["evidence_refs"] += [x for x in refs if x not in r["evidence_refs"]]

    def hst(name, role, refs=()):
        r = hosts.setdefault(name.lower(), {"name": name, "ip": None, "criticality": None, "roles": [],
                                            "evidence_refs": []})
        if role not in r["roles"]:
            r["roles"].append(role)
        r["evidence_refs"] += [x for x in refs if x not in r["evidence_refs"]]
        return r

    def ipr(ip, role, refs=()):
        r = ips.setdefault(ip, {"ip": ip, "roles": [], "internal": _internal(ip), "reputation": None,
                                "evidence_refs": []})
        if role not in r["roles"]:
            r["roles"].append(role)
        r["evidence_refs"] += [x for x in refs if x not in r["evidence_refs"]]
        return r

    if ents.get("account"):
        acc(ents["account"], "named in the alert")
    if ents.get("host"):
        hst(ents["host"], "named in the alert")["ip"] = ents.get("dst_ip")
    if ents.get("src_ip"):
        ipr(ents["src_ip"], "source in the alert")
    if ents.get("dst_ip"):
        ipr(ents["dst_ip"], f"alert host{' ' + ents['host'] if ents.get('host') else ''}")
    for e in a["timeline"]:
        role = f"{ROLE_BY_EVENT.get(e['event_type'], e['event_type'])} ({e['phase']})"
        ref = [e["evidence_ref"]]
        if e.get("account"):
            acc(e["account"], role, ref)
        if e.get("host"):
            hst(e["host"], role, ref)
    for name, r in accounts.items():
        inv_ref = f"inventory.json#accounts/{r['name']}"
        if inv_ref in evidence:
            r["inventory_role"] = evidence[inv_ref]["excerpt"]
            r["evidence_refs"].append(inv_ref)
    if f := facts.get("host_context"):
        h = hosts.get((ents.get("host") or "").lower())
        if h:
            h["criticality"] = (f.get("data") or {}).get("criticality")
            h["evidence_refs"] += [x for x in f["evidence_refs"] if x not in h["evidence_refs"]]
    if (f := facts.get("success_after_failures")) and f["data"].get("src_ip"):
        ipr(f["data"]["src_ip"], "source of the successful login", f["evidence_refs"][:1])
    if f := facts.get("failures_by_src_ip"):
        for ip in f["data"].get("counts", {}):
            ipr(ip, "source of failed logins", f["evidence_refs"][:2])
    if f := facts.get("post_compromise_outbound"):
        for d in f["data"].get("destinations", []):
            ipr(d["dst_ip"], "outbound destination after the login", f["evidence_refs"])
    for fid in ("source_ip_reputation", "outbound_destination_reputation"):
        if f := facts.get(fid):
            for ip, r in ips.items():
                if re.search(rf"(?<![\d.]){re.escape(ip)}(?!\.?\d)", f["statement"]):
                    r["reputation"] = f["statement"] if "MOCK" in f["statement"] else f"MOCK intel: {f['statement']}"
                    r["evidence_refs"] += [x for x in f["evidence_refs"] if x not in r["evidence_refs"]]
    return {"accounts": list(accounts.values()), "hosts": list(hosts.values()), "ips": list(ips.values())}


def _approval_status(rec: dict, actions: dict[str, dict]) -> str:
    if rec.get("pending_action_id") and rec["pending_action_id"] in actions:
        return actions[rec["pending_action_id"]]["status"]
    return "analyst_decision_required" if rec["requires_approval"] else "not_required"


def _recommendations(content: dict | None, actions: list[dict]) -> list[dict]:
    if not content:
        return []
    by_id = {x["id"]: x for x in actions}
    used = {r.get("pending_action_id") for r in content["recommendations"] if r.get("pending_action_id")}
    out = []
    for r in sorted(content["recommendations"], key=lambda r: r["priority"]):
        rec = {k: r[k] for k in ("priority", "action", "type", "rationale", "expected_impact", "evidence_refs",
                                 "requires_approval")}
        rec["pending_action_id"] = r.get("pending_action_id")
        rec["linked_by"] = "agent" if r.get("pending_action_id") else None
        if rec["type"] == "containment" and not rec["pending_action_id"]:
            # link a containment recommendation to the action requested for the target it names
            for x in actions:
                if x["id"] not in used and re.search(rf"(?<![\w.]){re.escape(x['target'])}(?![\w]|\.\d)",
                                                     r["action"], re.I) \
                        and re.search(_ACTION_WORDS[x["action_type"]], r["action"], re.I):
                    rec["pending_action_id"], rec["linked_by"] = x["id"], "code"
                    used.add(x["id"])
                    break
        rec["approval_status"] = _approval_status(rec, by_id)
        out.append(rec)
    return out


def build_report(store: Store, investigation_id: str) -> dict:
    inv = store.investigation(investigation_id)
    if inv is None:
        raise ReportError(f"no investigation {investigation_id}")
    out = store.latest_output(investigation_id, "assess", status="completed")
    if not out or not (out.get("assessment") or {}).get("findings"):
        raise ReportError(f"investigation {investigation_id} has no accepted assessment; nothing to report")
    a, plan = out["assessment"], out.get("plan") or {}
    f, chk, rub = a["findings"], a["severity_check"], a["rubric"]
    content = store.latest_output(investigation_id, "report", status="completed")
    t_now = datetime.now(timezone.utc)
    actions = [{**a, "status": "expired"} if a["status"] in ("pending", "approved") and
               parse_time(a["expires_at"]) <= t_now else a for a in store.actions(investigation_id)]
    decisions = {d["action_id"]: d for d in store.decisions(investigation_id)}
    sims = {s["action_id"]: s for s in store.simulated(investigation_id)}
    evidence = store.evidence(investigation_id)
    alert = inv["alert"]
    pv = a["provenance"]
    from soc_agent.correlate import condense_timeline

    plan_h = {h["id"]: h for h in plan.get("hypotheses", [])}
    closing = next((h for h in reversed(store.status_history(investigation_id)) if h["to_status"] == CLOSED), None)
    # the evidence label follows the data the tools actually read, not the alert's own marker
    data_synthetic = bool(pv.get("data_synthetic", inv["synthetic"]))
    faults = dict(pv.get("fault_injection") or {})
    labels = []
    if data_synthetic:
        labels.append("SYNTHETIC lab data (logs, assets)")
    if not inv["synthetic"]:
        labels.append("alert not marked synthetic")
    labels.append("MOCK intelligence feed / MOCK CVE database (live: false)")
    if inv["mock"]:
        labels.append("MOCK LLM: deterministic script, not an AI model")
    if faults:
        labels.append("FAULT INJECTION ACTIVE (testing only): " + ", ".join(f"{k}: {v}" for k, v in faults.items()))
    report = {
        "incident_id": investigation_id,
        "alert_id": inv["alert_id"],
        "version": 1,
        "title": f"{alert.get('title', 'Security alert')} - {(alert.get('entities') or {}).get('account', '?')} on "
                 f"{(alert.get('entities') or {}).get('host', '?')}",
        "status": inv["status"],
        "resolution": ({"note": inv["resolution"], "closed_by": inv["closed_by"] or closing["by"],
                        "closed_at": closing["at"]} if inv["status"] == CLOSED and closing else None),
        "severity": f["severity"], "severity_rationale": f["severity_rationale"],
        "severity_evidence_refs": f["severity_evidence_refs"],
        "confidence": f["confidence"], "confidence_rationale": f["confidence_rationale"],
        "executive_summary": ({"text": content["executive_summary"], "evidence_refs": content["summary_evidence_refs"],
                               "source": "agent"} if content else {"text": None, "evidence_refs": [], "source": "none"}),
        "affected_entities": _entities(alert, a, evidence),
        "timeline": [{"time": r["time"], "last_time": r["last_time"], "count": r["count"], "phase": r["phase"],
                      "event": _event_text(r), "evidence_refs": r["evidence_refs"]}
                     for r in condense_timeline(a["timeline"])],
        "assessment_summary": {
            "answers": [{"question": q, "claims": f[k]} for k, q in QUESTIONS.items()],
            "hypotheses": [{"id": h["id"], "description": plan_h.get(h["id"], {}).get("description", ""),
                            "benign": bool(plan_h.get(h["id"], {}).get("benign")), "status": h["status"],
                            "reasoning": h["reasoning"], "evidence_refs": h["evidence_refs"]} for h in f["hypotheses"]],
            "recommended_next_steps": f["recommended_next_steps"],
        },
        "alternative_explanations": f["alternative_explanations"],
        "gaps_unknowns": {"gaps": [{"id": g["id"], "statement": g["statement"]} for g in a["gaps"]],
                          "conflicts": [{"id": c["id"], "statement": c["statement"]} for c in a["conflicts"]],
                          "unknowns": f["unknowns"]},
        "mitre": f["mitre"],
        "recommendations": _recommendations(content, actions),
        "recommendations_source": ("agent (submit_report_content, validated)" if content else
                                   "none: the agent's report content was not accepted; see "
                                   "assessment_summary.recommended_next_steps"),
        "pending_actions": [{
            "action_id": x["id"], "action_type": x["action_type"], "target": x["target"], "status": x["status"],
            "requested_by": x["requested_by"], "reason": x["reason"], "evidence_refs": x["evidence_refs"],
            "expected_impact": x["expected_impact"], "created_at": x["created_at"], "expires_at": x["expires_at"],
            "decision": ({k: decisions[x["id"]][k] for k in ("decision", "analyst", "reason", "decided_at")}
                         if x["id"] in decisions else None),
            "simulated_execution": ({k: sims[x["id"]][k] for k in ("executed_by", "executed_at", "simulated_effect")}
                                    if x["id"] in sims else None)} for x in actions],
        "rubric_agreement": {"agent_severity": chk["agent_severity"], "rubric_severity": chk["rubric_severity"],
                             "agrees": chk["agrees"], "rubric_rule": chk["rubric_rule"],
                             "rubric_score": chk.get("rubric_score"), "agent_confidence": chk["agent_confidence"],
                             "rubric_confidence": chk["rubric_confidence"],
                             "confidence_agrees": chk["confidence_agrees"]},
        "provenance": {"runtime": "hermes-agent", "provider": pv["provider"], "model": pv["model"], "mock": pv["mock"],
                       "app_version": __version__, "plan_id": a.get("plan_id"),
                       "assembled_by": "code (soc_agent/report.py) from the stored assessment, evidence index and "
                                       "approval records",
                       "agent_contributed": (["executive_summary", "recommendations"] if content else [])
                       + ["findings (assessment phase, validated by submit_findings)"]},
        "data_labels": {"synthetic_data": data_synthetic, "alert_synthetic": bool(inv["synthetic"]),
                        "intel": "MOCK (live: false)", "mock_llm": bool(inv["mock"]), "fault_injection": faults,
                        "labels": labels},
        "evidence_appendix": [],
        "generated_at": now(),
    }
    cited = _refs({k: v for k, v in report.items() if k != "assessment_summary"}) + _refs(report["assessment_summary"])
    report["evidence_appendix"] = [{"ref": r, "tool": (evidence.get(r) or {}).get("tool", "?"),
                                    "excerpt": (evidence.get(r) or {}).get("excerpt") or "(not in the evidence index)"}
                                   for r in dict.fromkeys(cited)]
    return report


def report_problems(report: dict) -> list[str]:
    return problems(report, load_schema("incident_report"), limit=20)


# ------------------------------------------------------------------ Markdown
def _para(text) -> str:
    """Agent prose as ONE escaped paragraph: no new lines (so no forged headings / tables), no HTML, and a
    leading Markdown marker (#, >, -, *, +, |, =) is escaped."""
    s = _cell(text).strip()
    return ("\\" + s) if s[:1] in "#>-*+|=`~" and s else s


_MD_SPECIAL = re.compile(r"([\\`*\[\]|~])")     # links / images need [ ], emphasis * , code ` , tables |


def _cell(text) -> str:
    """One Markdown table cell / inline text: no new lines, and every character that could start Markdown syntax
    (emphasis, links, images, code, tables, HTML) is escaped, and URLs are not auto-linked: log text and agent
    prose are shown as data, never as Markdown."""
    s = "" if text is None else str(text)
    s = _MD_SPECIAL.sub(r"\\\1", s).replace("\r", " ").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")
    return s.replace("://", ":\\/\\/").replace("www.", "www\\.")


def _code(text) -> str:
    return "`" + str(text).replace("`", "'").replace("\n", " ").replace("|", "\\|") + "`"


def _r(refs: list[str], show: int = 3) -> str:
    if not refs:
        return "-"
    more = f" (+{len(refs) - show})" if len(refs) > show else ""
    return ", ".join(_code(x) for x in refs[:show]) + more


def render_markdown(r: dict) -> str:
    L: list[str] = []
    banner = []
    if r["data_labels"]["synthetic_data"] or "MOCK" in r["data_labels"]["intel"]:
        banner.append(f"**{SYNTHETIC_BANNER}**")
    if r["provenance"]["mock"]:
        banner.append(f"**{MOCK_LLM_BANNER}** produced by a deterministic script, not an AI model")
    if r["data_labels"].get("fault_injection"):
        banner.append("**FAULT INJECTION ACTIVE (testing only):** " + _cell(", ".join(
            f"{k}: {v}" for k, v in r["data_labels"]["fault_injection"].items())) + " - these failures were injected")
    L += [f"# Incident report {r['incident_id']} (v{r['version']})", ""]
    if banner:
        L += ["> " + "  \n> ".join(banner), ""]
    L += [f"_{_cell(r['title'])}_", "", "## Summary", "", "| field | value |", "|---|---|",
          f"| incident | {r['incident_id']} |", f"| alert | {_cell(r['alert_id'])} |",
          f"| status | **{r['status']}** |",
          f"| severity | **{r['severity'].upper()}** (rubric {r['rubric_agreement']['rubric_severity']}: "
          f"{'agrees' if r['rubric_agreement']['agrees'] else 'differs'}) |",
          f"| confidence | **{r['confidence'].upper()}** (rubric {r['rubric_agreement']['rubric_confidence']}) |",
          f"| pending actions | {sum(1 for x in r['pending_actions'] if x['status'] == 'pending')} awaiting an analyst "
          f"decision, {len(r['pending_actions'])} in total |",
          f"| generated by | {r['provenance']['runtime']} + {r['provenance']['provider']} "
          f"({_cell(r['provenance']['model'])}){' - MOCK' if r['provenance']['mock'] else ''} |",
          f"| data | {_cell('; '.join(r['data_labels']['labels']))} |",
          f"| generated at | {r['generated_at']} |", ""]
    if r.get("resolution"):
        L += [f"**Closed** by {_cell(r['resolution']['closed_by'])} at {r['resolution']['closed_at']}: "
              f"{_cell(r['resolution']['note'])}", ""]
    es = r["executive_summary"]
    L += ["## Executive summary", ""]
    L += [_para(es["text"]), "", f"Evidence: {_r(es['evidence_refs'], 6)}", ""] if es["text"] else \
        ["_No executive summary: the agent's report content was not accepted._", ""]
    L += ["## Severity and confidence", "",
          f"**Severity {r['severity'].upper()}.** {_cell(r['severity_rationale'])}", "",
          f"Evidence: {_r(r['severity_evidence_refs'], 8)}", "",
          f"**Confidence {r['confidence'].upper()}.** {_cell(r['confidence_rationale'])}", "",
          f"Rubric agreement: severity agent {r['rubric_agreement']['agent_severity']} / rubric "
          f"{r['rubric_agreement']['rubric_severity']} ({_cell(r['rubric_agreement']['rubric_rule'])}); confidence "
          f"{'agrees' if r['rubric_agreement']['confidence_agrees'] else 'differs'}.", ""]
    ae = r["affected_entities"]
    L += ["## Affected entities", "", "| kind | name | details | roles | evidence |", "|---|---|---|---|---|"]
    for x in ae["accounts"]:
        L.append(f"| account | {_cell(x['name'])} | {_cell(x.get('inventory_role') or '-')} | {_cell('; '.join(x['roles']))}"
                 f" | {_r(x['evidence_refs'], 2)} |")
    for x in ae["hosts"]:
        L.append(f"| host | {_cell(x['name'])} | ip {_cell(x.get('ip') or '?')}, criticality {_cell(x.get('criticality') or '?')}"
                 f" | {_cell('; '.join(x['roles']))} | {_r(x['evidence_refs'], 2)} |")
    for x in ae["ips"]:
        kind = {True: "internal", False: "external", None: "?"}[x["internal"]]
        L.append(f"| ip | {_cell(x['ip'])} | {kind}{'; ' + _cell(x['reputation']) if x.get('reputation') else ''} | "
                 f"{_cell('; '.join(x['roles']))} | {_r(x['evidence_refs'], 2)} |")
    L += ["", "## Timeline", "", "| time (UTC) | phase | event | count | evidence |", "|---|---|---|---|---|"]
    for t in r["timeline"]:
        L.append(f"| {t['time'][:19].replace('T', ' ')} | {_cell(t['phase'])} | {_cell(t['event'])} | {t['count']} | "
                 f"{_r(t['evidence_refs'], 2)} |")
    L += ["", "## Assessment", ""]
    for ans in r["assessment_summary"]["answers"]:
        L.append(f"**{_cell(ans['question'])}**")
        L.append("")
        L += [f"- {_cell(c['statement'])} [{_r(c['evidence_refs'], 3)}]" for c in ans["claims"]]
        L.append("")
    L += ["**Hypotheses**", "", "| id | hypothesis | status | reasoning | evidence |", "|---|---|---|---|---|"]
    for h in r["assessment_summary"]["hypotheses"]:
        L.append(f"| {h['id']}{' (benign)' if h['benign'] else ''} | {_cell(h['description'])} | **{h['status']}** | "
                 f"{_cell(h['reasoning'])} | {_r(h['evidence_refs'], 2)} |")
    L += ["", "## MITRE ATT&CK", "", "Only techniques the cited evidence justifies.", ""]
    if r["mitre"]:
        L += ["| technique | name | justification | evidence |", "|---|---|---|---|"]
        L += [f"| {_cell(m['technique_id'])} | {_cell(m['name'])} | {_cell(m['justification'])} | {_r(m['evidence_refs'], 3)} |"
              for m in r["mitre"]]
    else:
        L.append("_None justified by the evidence._")
    L += ["", "## Recommendations", "",
          f"Source: {_cell(r['recommendations_source'])}. Nothing is executed by the agent: containment and remediation "
          "need an analyst decision, and approved actions are only SIMULATED.", ""]
    if r["recommendations"]:
        L += ["| # | type | action | expected impact | approval | evidence |", "|---|---|---|---|---|---|"]
        for x in r["recommendations"]:
            appr = x["approval_status"].replace("_", " ")
            if x["pending_action_id"]:
                appr = f"{_code(x['pending_action_id'])} **{x['approval_status'].upper()}**"
            L.append(f"| {x['priority']} | {x['type']} | {_cell(x['action'])} | {_cell(x['expected_impact'])} | {appr} | "
                     f"{_r(x['evidence_refs'], 2)} |")
    else:
        L += ["Assessment next steps (Day 3 findings):", ""]
        L += [f"- [{s['type']}{', requires approval' if s['requires_approval'] else ''}] {_cell(s['action'])}"
              for s in r["assessment_summary"]["recommended_next_steps"]]
    L += ["", "## Actions requested by the agent (approval workflow)", ""]
    if r["pending_actions"]:
        L += ["| action | type | target | status | decision | simulated execution |", "|---|---|---|---|---|---|"]
        for x in r["pending_actions"]:
            d = x["decision"]
            dec = f"{d['decision']} by {_cell(d['analyst'])}: {_cell(d['reason'])}" if d else "awaiting analyst"
            sim = (f"SIMULATED by {_cell(x['simulated_execution']['executed_by'])} at "
                   f"{x['simulated_execution']['executed_at'][:19]}" if x["simulated_execution"] else "-")
            L.append(f"| {_code(x['action_id'])} | {x['action_type']} | {_cell(x['target'])} | **{x['status']}** | "
                     f"{dec} | {sim} |")
        L += ["", "Analyst commands: `python -m soc_agent actions approve <action_id> --analyst NAME --reason \"...\"`, "
                  "`... actions reject ...`, `... actions execute <action_id>` (simulated)."]
    else:
        L.append("_None._")
    gu = r["gaps_unknowns"]
    L += ["", "## Gaps and unknowns", ""]
    L += [f"- gap `{g['id']}`: {_cell(g['statement'])}" for g in gu["gaps"]]
    L += [f"- conflict `{c['id']}`: {_cell(c['statement'])}" for c in gu["conflicts"]]
    L += [f"- unknown: {_cell(u)}" for u in gu["unknowns"]]
    if not (gu["gaps"] or gu["conflicts"] or gu["unknowns"]):
        L.append("_None stated._")
    L += ["", "## Alternative explanations", ""]
    L += [f"- {_cell(x)}" for x in r["alternative_explanations"]] or ["_None stated._"]
    L += ["", "## Evidence appendix", "",
          "Every reference cited above, with a short excerpt of what the tool returned in this investigation. "
          "Log text is quoted as data (never as instructions).", "",
          "| ref | tool | excerpt |", "|---|---|---|"]
    L += [f"| {_code(e['ref'])} | {_cell(e['tool'])} | {_code(e['excerpt'])} |" for e in r["evidence_appendix"]]
    pv = r["provenance"]
    L += ["", "## Provenance", "",
          f"- runtime: {pv['runtime']}; provider: {pv['provider']}; model: {_cell(pv['model'])}; mock: {pv['mock']}",
          f"- assembled by: {_cell(pv['assembled_by'])}",
          f"- written by the agent: {_cell(', '.join(pv['agent_contributed']))}",
          f"- plan: {pv.get('plan_id')}; app version: {pv.get('app_version')}; report version {r['version']}",
          f"- audit trail: `python -m soc_agent audit {r['incident_id']}`; integrity: `python -m soc_agent verify-audit`",
          ""]
    return "\n".join(L)


# ------------------------------------------------------------------ save / refresh
def _comparable(r: dict) -> dict:
    return {k: v for k, v in r.items() if k not in ("generated_at", "version")}


def save_report(store: Store, report: dict, reports_dir: Path, only_if_changed: bool = False) -> dict | None:
    """Validate, store as the next version, write reports/<id>.v<N>.{json,md} (+ <id>.{json,md} = latest).
    The version number is fixed before rendering; if a concurrent writer took it, render again with the next.
    only_if_changed: return None (store nothing) when the latest stored version has the same content."""
    for _ in range(5):
        latest = store.report(report["incident_id"])
        if only_if_changed and latest and _comparable(latest["json"]) == _comparable(report):
            return None
        report = {**report, "version": (latest or {}).get("version", 0) + 1}
        if issues := report_problems(report):
            raise SchemaError("incident report", issues)
        md = render_markdown(report)
        try:
            version = store.add_report(report["incident_id"], report, md)
            break
        except StoreError:
            continue
    else:
        raise StoreError(f"could not store a new report version for {report['incident_id']}")
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    paths = {}
    for suffix, body in ((".json", text), (".md", md)):
        p = reports_dir / f"{report['incident_id']}.v{version}{suffix}"
        p.write_text(body, encoding="utf-8", errors="replace")
        (reports_dir / f"{report['incident_id']}{suffix}").write_text(body, encoding="utf-8", errors="replace")
        paths[suffix[1:]] = str(p)
    return {"version": version, "json_path": paths["json"], "md_path": paths["md"], "report": report, "markdown": md}


def refresh_report(store: Store, investigation_id: str, reports_dir: Path) -> dict | None:
    """Rebuild the report from the database; store a new version only if something changed (status, approval
    status, decisions, ...). Returns the saved version info, or None if nothing changed / no report exists."""
    latest = store.report(investigation_id)
    if latest is None:
        return None
    return save_report(store, build_report(store, investigation_id), reports_dir, only_if_changed=True)


