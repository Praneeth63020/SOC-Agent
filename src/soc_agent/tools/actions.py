"""Day 4: what the agent may do about containment - REQUEST it, nothing more.

request_action [write_internal] is the agent's only path toward a disruptive action. It records a pending
request for a human analyst and moves the investigation to Awaiting Approval. It never approves or executes.
Checks (besides the strict schema, additionalProperties: false - so "approved", "analyst", "status", ... are
rejected by the wrapper before the handler runs):
  - every evidence_ref was returned by a tool in this investigation
  - the target is named in the alert entities or in this investigation's evidence (no invented targets), with
    the right kind: block_ip -> an IP, disable_account -> an account, isolate_host -> a host; and at least one
    cited ref concerns the target (or the alert names it)
  - the target is not protected SOC / security infrastructure (data/assets/protected_assets.json)
  - consistency (Day 5): the accepted findings of this investigation recommend it - a containment claim or a
    containment next step names the action (block / disable / isolate) and the target (by name or by a cited
    ref about it); a request that contradicts the agent's own findings would make the report misleading
  - no duplicate: the same action_type + target is not already pending or approved
  - at most MAX_ACTION_REQUESTS accepted requests (MAX_REQUEST_CALLS calls) per phase run

block_ip / disable_account / isolate_host themselves (DISRUPTIVE_TOOLS, permission "disruptive") are defined
here for completeness and are NEVER registered with Hermes: register_tools refuses them, and the wrapper denies
the permission in any run. The analyst path (soc_agent/approvals.py) never goes through this module.
"""
from __future__ import annotations

import ipaddress
import json
import re
from functools import lru_cache

from soc_agent.config import PROJECT_ROOT
from soc_agent.schemas import load_tool_schema
from soc_agent.tools.base import RunContext, ToolFailure, ToolRejection, ToolSpec

PROTECTED_FILE = PROJECT_ROOT / "data" / "assets" / "protected_assets.json"   # never the scenario's data_dir
MAX_ACTION_REQUESTS = 6           # accepted requests per phase run
MAX_REQUEST_CALLS = 12            # request_action calls per phase run, rejected ones included
TARGET_KIND = {"block_ip": "ip", "disable_account": "account", "isolate_host": "host"}
ACTION_WORDS = {"block_ip": r"\bblock", "disable_account": r"\b(disable|lock|suspend)", "isolate_host": r"\bisolat"}
_NOT_RECOMMENDED = re.compile(r"\bno (immediate |further )?containment\b|\bnot (needed|required|indicated|necessary|"
                              r"warranted)\b|\bdo not\b|\bno need\b", re.I)


def findings_recommend(action: str, target: str, ctx: RunContext) -> bool | None:
    """Do this investigation's accepted findings recommend `action` on `target`? None = no findings in the run
    (e.g. a direct tool test). A containment claim or containment next step must use the action's word (block /
    disable / isolate), not say it is not needed, and name the target or cite a ref whose entities include it."""
    f = ctx.findings
    if not f:
        return None
    t = target.strip().lower()
    texts = [(c["statement"], c.get("evidence_refs") or []) for c in f.get("containment") or []]
    texts += [(s["action"], []) for s in f.get("recommended_next_steps") or [] if s.get("type") == "containment"]
    for text, refs in texts:
        if not re.search(ACTION_WORDS[action], text, re.I) or _NOT_RECOMMENDED.search(text):
            continue
        named = re.search(rf"(?<![\w.-]){re.escape(t)}(?![\w-]|\.\d)", text.lower()) is not None
        cited = any(t in {str(x).lower() for x in [(ctx.evidence_index.get(r) or {}).get("account"),
                                                    (ctx.evidence_index.get(r) or {}).get("host"),
                                                    *((ctx.evidence_index.get(r) or {}).get("ips") or [])]}
                    for r in refs)
        if named or cited:
            return True
    return False


@lru_cache(maxsize=1)
def protected_assets() -> dict:
    data = json.loads(PROTECTED_FILE.read_text(encoding="utf-8"))
    return {"hosts": {h.lower() for h in data.get("hosts", [])},
            "ips": set(data.get("ips", [])),
            "networks": [ipaddress.ip_network(n) for n in data.get("networks", [])],
            "accounts": {a.lower() for a in data.get("accounts", [])}}


def protected_reason(action_type: str, target: str) -> str | None:
    """Why `target` must never be the target of `action_type` (None = not protected)."""
    p, kind, t = protected_assets(), TARGET_KIND[action_type], target.strip()
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(t)
        except ValueError:
            return None
        if t in p["ips"] or any(ip in n for n in p["networks"]):
            return f"{t} is protected SOC / security infrastructure (data/assets/protected_assets.json)"
    elif kind == "host" and t.lower() in p["hosts"]:
        return f"host {t} is protected SOC / security infrastructure (data/assets/protected_assets.json)"
    elif kind == "account" and t.lower() in p["accounts"]:
        return f"account {t} is a protected system / SOC account (data/assets/protected_assets.json)"
    return None


def known_targets(ctx: RunContext) -> dict[str, dict[str, set[str]]]:
    """kind -> {target (lower case) -> refs that name it} from the alert entities and this investigation's
    evidence. Only entity FIELDS count (account, host, IPs): text inside a log message (e.g. an injected
    instruction naming "admin") never makes something a valid target."""
    out: dict[str, dict[str, set[str]]] = {"ip": {}, "account": {}, "host": {}}
    ents = ctx.alert.get("entities") or {}
    for kind, keys in (("ip", ("src_ip", "dst_ip")), ("account", ("account",)), ("host", ("host",))):
        for k in keys:
            if ents.get(k):
                out[kind].setdefault(str(ents[k]).lower(), set()).add("<alert>")
    for ref, ev in ctx.evidence_index.items():
        if ev.get("account"):
            out["account"].setdefault(ev["account"].lower(), set()).add(ref)
        if ev.get("host"):
            out["host"].setdefault(ev["host"].lower(), set()).add(ref)
        for ip in ev.get("ips") or []:
            out["ip"].setdefault(ip, set()).add(ref)
    return out


def action_problems(args: dict, ctx: RunContext) -> list[str]:
    issues: list[str] = []
    action, target = args["action_type"], args["target"].strip()
    kind = TARGET_KIND[action]
    for ref in args["evidence_refs"]:
        if ref not in ctx.evidence_refs:
            issues.append(f"evidence_refs: {ref!r} was not returned by any tool in this investigation")
    if kind == "ip":
        try:
            ipaddress.IPv4Address(target)
        except ValueError:
            issues.append(f"target: {action} needs an IPv4 address, not {target!r}")
    known = known_targets(ctx)[kind]
    refs_for_target = known.get(target.lower())
    if not refs_for_target:
        issues.append(f"target: {kind} {target!r} does not appear in the alert entities or in this investigation's "
                      f"evidence; a request may only target an {kind} the evidence names (invented targets are "
                      "refused)")
    elif "<alert>" not in refs_for_target and not refs_for_target & set(args["evidence_refs"]):
        issues.append(f"evidence_refs: none of the cited refs concerns {target}; cite the evidence that names it "
                      f"(e.g. {sorted(refs_for_target)[0]})")
    if refs_for_target and findings_recommend(action, target, ctx) is False:
        issues.append(f"consistency: your accepted findings do not recommend {action} for {target} (no containment "
                      "claim or containment next step names it); request only containment the findings recommend. "
                      "Anything else belongs in an investigative recommendation for the analyst")
    if why := protected_reason(action, target):
        issues.append(f"target: {why}; it can never be the target of {action}")
    return issues


def _request_action(args: dict, ctx: RunContext) -> dict:
    from soc_agent.store import StoreError

    if ctx.store is None:
        raise ToolFailure("No investigation database is available; the request was not recorded.")
    calls = [c for c in ctx.tool_calls if c["tool"] == REQUEST_ACTION.name]
    if len(calls) >= MAX_REQUEST_CALLS:
        raise ToolRejection(f"Too many request_action calls in this run (limit {MAX_REQUEST_CALLS}).")
    if sum(c["status"] == "ok" for c in calls) >= MAX_ACTION_REQUESTS:
        raise ToolRejection(f"Too many action requests in this run (limit {MAX_ACTION_REQUESTS} accepted).")
    if issues := action_problems(args, ctx):
        raise ToolRejection("Action request rejected; nothing was recorded.", issues,
                            "Only request containment the evidence of this investigation supports, for targets it "
                            "names. You cannot approve or execute actions; an analyst decides.")
    try:
        row = ctx.store.add_pending_action(ctx.investigation_id, args["action_type"], args["target"].strip(),
                                           args["reason"], args["evidence_refs"], args["expected_impact"],
                                           requested_by="agent", phase=ctx.phase or "report")
    except StoreError as e:
        raise ToolRejection(f"Action request rejected: {e}.") from None
    return {"accepted": True, "action_id": row["id"], "status": "pending", "expires_at": row["expires_at"],
            "message": (f"Recorded {row['id']} as PENDING for an analyst decision. Nothing was executed, and you "
                        "cannot approve or execute it. Cite this action_id as pending_action_id in the matching "
                        "recommendation.")}


REQUEST_ACTION = ToolSpec(
    name="request_action",
    description=("REQUEST a containment action for a human analyst to decide: action_type block_ip | disable_account "
                 "| isolate_host, target (as named in the alert or in this investigation's evidence), reason, "
                 "evidence_refs (refs returned in this investigation) and expected_impact. It only records a pending "
                 "request; nothing is executed, and you can never approve or execute it. Returns the action_id."),
    parameters=load_tool_schema("request_action", "input"),
    handler=_request_action,
    permission="write_internal",
    output_schema=load_tool_schema("request_action", "output"),
    summarize=lambda r: f"{r['action_id']} recorded as pending (analyst decision required; nothing executed)",
    retry_hint="Call request_action with exactly: action_type, target, reason, evidence_refs, expected_impact.",
)


# ------------------------------------------------ never registered with Hermes
def _never(args: dict, ctx: RunContext) -> dict:
    raise ToolRejection("Disruptive actions are never executed by the agent. Use request_action; an analyst "
                        "decides and executes (simulated) through the approval workflow.")


def _disruptive(name: str, what: str) -> ToolSpec:
    return ToolSpec(name=name, description=f"{what} (DISRUPTIVE: analyst approval path only, simulated).",
                    parameters=load_tool_schema("disruptive_action", "input"), handler=_never,
                    permission="disruptive")


BLOCK_IP = _disruptive("block_ip", "Block an IP address at the perimeter")
DISABLE_ACCOUNT = _disruptive("disable_account", "Disable a user account")
ISOLATE_HOST = _disruptive("isolate_host", "Isolate a host from the network")
DISRUPTIVE_TOOLS = [BLOCK_IP, DISABLE_ACCOUNT, ISOLATE_HOST]
assert {t.name for t in DISRUPTIVE_TOOLS} == set(TARGET_KIND) == set(
    load_tool_schema("request_action", "input")["properties"]["action_type"]["enum"])
