"""Planning-phase tools: read the alert, submit the investigation plan.

The plan names which evidence tools (tools/evidence.py: search_logs, lookup_ip,
search_cve, get_asset_context) each step will use; the investigation phase
(investigator.py) then runs them.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Iterator

from soc_agent.schemas import load_schema, load_tool_schema, problems
from soc_agent.tools.base import RunContext, ToolRejection, ToolSpec

MAX_PLAN_ATTEMPTS = 3              # content-checked plan submissions
MAX_PLAN_FORMAT_REJECTIONS = 3     # separate budget for schema (format) rejections (as for findings)

# parameter keys whose values must be an account / host named in the alert
ACCOUNT_KEYS = {"account", "user", "username", "user_name", "dstuser", "srcuser", "target_user"}
HOST_KEYS = {"host", "hostname", "asset", "agent", "agent_name", "dst_host", "src_host", "computer"}
# software versions such as "8.9.1.2" look like IPv4 addresses but are not indicators
VERSION_KEYS = {"version", "product_version", "software_version", "cpe"}
# an IPv4 address not embedded in a longer dotted number; a trailing sentence period is allowed
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")


# --------------------------------------------------------------------- get_alert
def _get_alert(args: dict, ctx: RunContext) -> dict:
    if args["alert_id"] != ctx.alert["alert_id"]:
        raise ToolRejection(f"Unknown alert_id '{args['alert_id']}'. This investigation is for "
                            f"'{ctx.alert['alert_id']}'.")
    alert = {k: v for k, v in ctx.alert.items() if k != "raw"}   # data minimization: raw stays local
    return {"alert": alert,
            "data_label": "SYNTHETIC LAB DATA" if ctx.alert.get("synthetic") else "NOT MARKED SYNTHETIC"}


GET_ALERT = ToolSpec(
    name="get_alert",
    description=("Return the normalized security alert under investigation: rule, severity hint, entities "
                 "(account, host, IPs, port, service) and observations. Call this first."),
    parameters={"type": "object",
                "properties": {"alert_id": {"type": "string", "minLength": 3, "maxLength": 64,
                                            "description": "The alert id given in the task."}},
                "required": ["alert_id"], "additionalProperties": False},
    handler=_get_alert,
    permission="read",
    output_schema=load_tool_schema("get_alert", "output"),
    summarize=lambda r: f"alert {r['alert']['alert_id']} ({r['data_label']})",
    evidence_source=False,           # the alert is the subject, not evidence (and may carry forged refs)
)


# ------------------------------------------------------- no invented indicators
def _walk(value: Any, key: str | None = None) -> Iterator[tuple[str | None, str]]:
    """Yield (key, string value) pairs from nested parameters."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(v, str(k).lower())
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v, key)
    elif value is not None:
        yield key, str(value)


def unsupported_values(plan: dict, alert: dict) -> list[str]:
    """IPs, accounts and hosts in step parameters must appear in the alert's entities."""
    ents = alert.get("entities", {})
    ips = {str(ents[k]) for k in ("src_ip", "dst_ip") if ents.get(k)}
    accounts = {str(ents["account"]).lower()} if ents.get("account") else set()
    hosts = {str(ents["host"]).lower()} if ents.get("host") else set()
    issues = []
    for step in plan.get("steps") or []:
        if not isinstance(step, dict):
            continue
        n = step.get("step", "?")
        for key, text in _walk(step.get("parameters") or {}):
            for ip in ([] if key in VERSION_KEYS else _IPV4.findall(text)):
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    issues.append(f"step {n}: {ip!r} is not a valid IP address")
                    continue
                if ip not in ips:
                    issues.append(f"step {n}: IP {ip} does not appear in the alert")
            if key in ACCOUNT_KEYS and text.lower() not in accounts:
                issues.append(f"step {n}: {key}={text!r} is not an account in the alert")
            if key in HOST_KEYS and text.lower() not in hosts and text not in ips:   # a host may be named by IP
                issues.append(f"step {n}: {key}={text!r} is not a host in the alert")
    return issues


def plan_problems(plan: Any, alert: dict) -> list[str]:
    """Everything that is wrong with a submitted plan (empty list = acceptable)."""
    issues = problems(plan, load_schema("investigation_plan"), limit=12)
    if not isinstance(plan, dict):
        return issues
    steps = [s.get("step") for s in plan.get("steps") or [] if isinstance(s, dict)]
    if steps and steps != list(range(1, len(steps) + 1)):
        issues.append(f"steps must be numbered 1..{len(steps)} in order (got {steps})")
    ids = [h.get("id") for h in plan.get("hypotheses") or [] if isinstance(h, dict)]
    if len(ids) != len(set(ids)):
        issues.append("hypothesis ids must be unique")
    return issues + unsupported_values(plan, alert)


def plan_quality_notes(plan: dict) -> list[str]:
    """Non-blocking observations about an ACCEPTED plan (shown as warnings, never a rejection)."""
    steps = [s for s in plan.get("steps") or [] if isinstance(s, dict)]
    notes = []
    reviews = [s.get("step") for s in steps if s.get("tool") == "analyst_review"]
    if len(reviews) > 1:
        notes.append(f"Plan has {len(reviews)} analyst_review steps {reviews}; one combined review step "
                     "is expected.")
    seen: dict[str, int] = {}
    for s in steps:
        key = json.dumps([s.get("tool"), s.get("parameters")], sort_keys=True)
        if key in seen and s.get("tool") != "analyst_review":
            notes.append(f"Step {s.get('step')} repeats step {seen[key]} (same tool and parameters).")
        seen.setdefault(key, s.get("step"))
    return notes


# -------------------------------------------------------- submit_investigation_plan
def _format_rejected(call: dict) -> bool:
    res = call.get("result") if isinstance(call.get("result"), dict) else {}
    return call["status"] == "rejected" and str(res.get("error", "")).startswith("Invalid arguments")


def _plan_budget(args: dict, ctx: RunContext) -> tuple[dict, list[str]]:
    """Runs before validation: format (schema) rejections have their own budget, so they do not use up the
    content-checked attempts (a live model lost a plan to three different format slips)."""
    if ctx.plan is None:
        calls = [c for c in ctx.tool_calls if c["tool"] == SUBMIT_PLAN.name]
        if (sum(map(_format_rejected, calls)) >= MAX_PLAN_FORMAT_REJECTIONS
                or sum(not _format_rejected(c) for c in calls) >= MAX_PLAN_ATTEMPTS):
            raise ToolRejection(f"Too many plan submissions (limits: {MAX_PLAN_ATTEMPTS} checked, "
                                f"{MAX_PLAN_FORMAT_REJECTIONS} with format errors). Stop and report failure.")
    return args, []


def _submit_plan(args: dict, ctx: RunContext) -> dict:
    if ctx.plan is not None:
        raise ToolRejection("A plan was already accepted for this investigation. Do not submit again.")
    attempts = 1 + sum(1 for c in ctx.tool_calls if c["tool"] == SUBMIT_PLAN.name and not _format_rejected(c))
    if attempts > MAX_PLAN_ATTEMPTS:
        raise ToolRejection(f"Too many plan submissions (limit {MAX_PLAN_ATTEMPTS}). Stop and report failure.")
    if issues := plan_problems(args, ctx.alert):
        raise ToolRejection("Plan rejected.", issues,
                            f"Fix exactly these problems and call submit_investigation_plan again "
                            f"(attempt {attempts} of {MAX_PLAN_ATTEMPTS}).")
    ctx.plan = dict(args)
    return {"accepted": True, "message": "Plan stored. Reply with one short sentence; do not repeat the plan."}


def _plan_argument_schema() -> dict:
    # The plan's six fields ARE the arguments (no nested {"plan": {...}}): live NVIDIA runs repeatedly sent
    # that one nested object argument as a malformed JSON string. The wrapper validates the FULL plan schema;
    # the model is sent the simplified one (model_schema); the handler adds numbering + indicator checks.
    return {k: v for k, v in load_schema("investigation_plan").items() if k not in ("$id", "title")}


SUBMIT_PLAN = ToolSpec(
    name="submit_investigation_plan",
    description=("Submit the structured investigation plan for the current alert (exactly once). The arguments "
                 "are the plan itself: summary (string) and hypotheses, key_questions, steps, safety_notes, "
                 "data_gaps (JSON arrays, never strings containing JSON). Every step needs all six fields, "
                 "including expected_evidence. It is validated against the investigation-plan schema and checked "
                 "for indicators that are not in the alert; if problems are returned, fix them and resubmit."),
    # The wrapper rejects schema errors before the handler runs (audited; they count towards
    # MAX_PLAN_ATTEMPTS); the handler then checks step numbering and invented indicators.
    parameters=_plan_argument_schema(),
    prepare=_plan_budget,
    handler=_submit_plan,
    permission="write_internal",
    output_schema=load_tool_schema("submit_investigation_plan", "output"),
    summarize=lambda r: "plan accepted",
)

DAY1_TOOLS = [GET_ALERT, SUBMIT_PLAN]
