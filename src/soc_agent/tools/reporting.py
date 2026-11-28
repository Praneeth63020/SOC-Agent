"""Day 4 report-phase tool: submit_report_content [write_internal].

The agent's ONLY contribution to the incident report: an executive summary (<= 150 words) and prioritized
recommendations. Everything else in the report (severity, confidence, entities, timeline, MITRE, gaps,
evidence appendix, approval status) is assembled by code from the stored assessment (report.py).

Checks (besides the strict schema applied by the wrapper):
  - the executive summary has at most MAX_SUMMARY_WORDS words; it and every recommendation cite refs returned
    by tools in this investigation (summary_evidence_refs / evidence_refs)
  - IP reputation in the summary rests on a cited lookup_ip ref and says MOCK intel (same rule as the findings)
  - containment and remediation need requires_approval: true; an "investigative" item that is really a
    containment action (block, disable, isolate, reset a password, ...) is refused
  - priorities are unique; pending_action_id must be an action requested in this investigation, used by one
    containment recommendation; every action requested in this run must be cited by one
  - at most MAX_REPORT_ATTEMPTS submissions; accepted once
"""
from __future__ import annotations

import re

from soc_agent.schemas import load_tool_schema
from soc_agent.tools.assessment import _CONTAINMENT, _reputation_problems
from soc_agent.tools.base import RunContext, ToolFailure, ToolRejection, ToolSpec

MAX_SUMMARY_WORDS = 150
MAX_REPORT_ATTEMPTS = 3
_WORD = re.compile(r"\S+")


def report_content_problems(args: dict, ctx: RunContext, actions: list[dict]) -> list[str]:
    issues: list[str] = []
    known_rep_ips = {r.split("#", 1)[1] for r, tool in ctx.evidence_refs.items() if tool == "lookup_ip"}

    def check_refs(where: str, refs: list[str]) -> None:
        for ref in refs:
            if ref not in ctx.evidence_refs:
                issues.append(f"{where}: evidence_ref {ref!r} was not returned by any tool in this investigation")

    words = len(_WORD.findall(args["executive_summary"]))
    if words > MAX_SUMMARY_WORDS:
        issues.append(f"executive_summary: {words} words; at most {MAX_SUMMARY_WORDS}")
    check_refs("summary_evidence_refs", args["summary_evidence_refs"])
    issues += _reputation_problems("executive_summary", args["executive_summary"], args["summary_evidence_refs"],
                                   ctx, known_rep_ips, set(), refs_field="summary_evidence_refs")

    by_id = {a["id"]: a for a in actions}
    prios = [r["priority"] for r in args["recommendations"]]
    if dup := sorted({p for p in prios if prios.count(p) > 1}):
        issues.append(f"recommendations: priority {dup} used more than once; give each recommendation its own "
                      "priority (1 = most urgent)")
    cited_actions: dict[str, int] = {}
    for i, r in enumerate(args["recommendations"], 1):
        where = f"recommendations {i}"
        check_refs(where, r["evidence_refs"])
        if r["type"] in ("containment", "remediation") and r["requires_approval"] is not True:
            issues.append(f"{where}: {r['type']} needs requires_approval: true (an analyst decides; nothing is "
                          "executed by the agent)")
        if r["type"] == "investigative" and (m := _CONTAINMENT.search(r["action"])):
            issues.append(f"{where}: {m.group(0)!r} is a containment action; set type containment and "
                          "requires_approval: true")
        if pid := r.get("pending_action_id"):
            a = by_id.get(pid)
            if a is None:
                issues.append(f"{where}: pending_action_id {pid} is not an action requested in this investigation "
                              f"(requested: {sorted(by_id) or 'none'})")
            elif r["type"] != "containment":
                issues.append(f"{where}: pending_action_id {pid} ({a['action_type']} {a['target']}) belongs to a "
                              "containment recommendation; set type containment")
            if pid in cited_actions:
                issues.append(f"{where}: pending_action_id {pid} is already used by recommendations "
                              f"{cited_actions[pid]}")
            cited_actions.setdefault(pid, i)
        issues += _reputation_problems(f"{where}", r["action"] + " " + r["rationale"], None, ctx, known_rep_ips, set())
    requested_now = [a for a in actions if a.get("phase") == (ctx.phase or "report") and a["id"] in
                     {(c.get("result") or {}).get("action_id") for c in ctx.tool_calls if c["status"] == "ok"}]
    for a in requested_now:
        if a["id"] not in cited_actions:
            issues.append(f"recommendations: action {a['id']} ({a['action_type']} {a['target']}) was requested in "
                          "this run; add it as a containment recommendation with pending_action_id "
                          f"\"{a['id']}\"")
    return issues


def _submit_report_content(args: dict, ctx: RunContext) -> dict:
    if ctx.report_content is not None:
        raise ToolRejection("Report content was already accepted for this investigation. Do not submit again.")
    attempts = 1 + sum(1 for c in ctx.tool_calls if c["tool"] == SUBMIT_REPORT_CONTENT.name)
    if attempts > MAX_REPORT_ATTEMPTS:
        raise ToolRejection(f"Too many report submissions (limit {MAX_REPORT_ATTEMPTS}). Stop and report failure.")
    if ctx.store is None:
        raise ToolFailure("No investigation database is available.")
    actions = ctx.store.actions(ctx.investigation_id)
    if issues := report_content_problems(args, ctx, actions):
        raise ToolRejection("Report content rejected.", issues,
                            f"Fix exactly these problems and call submit_report_content again with all three fields "
                            f"(attempt {attempts} of {MAX_REPORT_ATTEMPTS}). Cite only evidence_ref strings exactly as "
                            "tools returned them in this investigation.")
    ctx.report_content = args
    return {"accepted": True, "message": "Report content stored. The report is assembled by code. Reply with one "
                                         "short sentence."}


SUBMIT_REPORT_CONTENT = ToolSpec(
    name="submit_report_content",
    description=("Submit your part of the incident report (exactly once, after any request_action calls): "
                 "executive_summary (<= 150 words, plain language), summary_evidence_refs, and recommendations "
                 "[{priority (1 = most urgent), action, type investigative|containment|remediation, rationale, "
                 "expected_impact, evidence_refs, requires_approval, pending_action_id?}]. Containment and "
                 "remediation need requires_approval: true; a containment you requested with request_action cites its "
                 "action_id as pending_action_id. Everything else in the report is built by code."),
    parameters=load_tool_schema("submit_report_content", "input"),
    handler=_submit_report_content,
    permission="write_internal",
    output_schema=load_tool_schema("submit_report_content", "output"),
    summarize=lambda r: "report content accepted",
    retry_hint="Call submit_report_content again with executive_summary, summary_evidence_refs and recommendations.",
)

REPORT_TOOLS_AGENT = [SUBMIT_REPORT_CONTENT]
