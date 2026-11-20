"""Day 1 tools: read the alert, submit the investigation plan.

Evidence tools (search_logs, lookup_ip, search_cve, get_asset_context) arrive on
Day 2; on Day 1 the agent only *plans* which of them it will use.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Iterator

from soc_agent.schemas import load_schema, problems
from soc_agent.tools.base import RunContext, ToolRejection, ToolSpec

MAX_PLAN_ATTEMPTS = 3

# parameter keys whose values must be an account / host named in the alert
ACCOUNT_KEYS = {"account", "user", "username", "user_name", "dstuser", "srcuser", "target_user"}
HOST_KEYS = {"host", "hostname", "asset", "agent", "agent_name", "dst_host", "src_host", "computer"}
# software versions such as "8.9.1.2" look like IPv4 addresses but are not indicators
VERSION_KEYS = {"version", "product_version", "software_version", "cpe"}
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


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
def _submit_plan(args: dict, ctx: RunContext) -> dict:
    if ctx.plan is not None:
        raise ToolRejection("A plan was already accepted for this investigation. Do not submit again.")
    attempts = 1 + sum(1 for c in ctx.tool_calls if c["tool"] == SUBMIT_PLAN.name)
    if attempts > MAX_PLAN_ATTEMPTS:
        raise ToolRejection(f"Too many plan submissions (limit {MAX_PLAN_ATTEMPTS}). Stop and report failure.")
    if issues := plan_problems(args["plan"], ctx.alert):
        raise ToolRejection("Plan rejected.", issues,
                            f"Fix exactly these problems and call submit_investigation_plan again "
                            f"(attempt {attempts} of {MAX_PLAN_ATTEMPTS}).")
    ctx.plan = args["plan"]
    return {"accepted": True, "message": "Plan stored. Reply with one short sentence; do not repeat the plan."}


_MODEL_SCHEMA_DROP = {"$schema", "$id", "title", "contains", "pattern", "format"}


def _for_model(schema: dict) -> dict:
    """The plan schema without keywords some OpenAI-compatible backends reject in tool definitions.
    Nothing is lost: the handler re-validates every plan against the FULL schema."""
    out = {k: v for k, v in schema.items() if k not in _MODEL_SCHEMA_DROP}
    if isinstance(out.get("properties"), dict):
        out["properties"] = {name: _for_model(sub) for name, sub in out["properties"].items()}
    if isinstance(out.get("items"), dict):
        out["items"] = _for_model(out["items"])
    return out


def _plan_argument_schema() -> dict:
    plan = _for_model(load_schema("investigation_plan"))
    plan["description"] = "The complete plan as a JSON object (not a string containing JSON)."
    return {"type": "object", "properties": {"plan": plan}, "required": ["plan"], "additionalProperties": False}


SUBMIT_PLAN = ToolSpec(
    name="submit_investigation_plan",
    description=("Submit the structured investigation plan for the current alert (exactly once), passing "
                 "`plan` as a JSON object. Every step needs all six fields, including expected_evidence. It is "
                 "validated against the investigation-plan schema and checked for indicators that are not "
                 "in the alert; if problems are returned, fix them and resubmit."),
    # The wrapper rejects structural errors before the handler runs (audited; they count
    # towards MAX_PLAN_ATTEMPTS); the handler then applies the full schema and the indicator check.
    parameters=_plan_argument_schema(),
    handler=_submit_plan,
    permission="write_internal",
)

DAY1_TOOLS = [GET_ALERT, SUBMIT_PLAN]
