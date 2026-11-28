"""Investigation-phase tool: submit_evidence_log (write_internal).

The evidence log records, per plan step, which tool was used, why, the outcome
(found / none / failed) and the evidence refs. It only counts if it is submitted
through this tool and accepted. Besides the schema, it must be consistent with
what actually happened in THIS run (the audit trail):
  - every evidence_ref was returned by a tool call in this run, by the step's tool
    (a ref that was never returned is rejected: no invented evidence)
  - "found" cites at least one ref; "none" and "failed" cite none
  - "failed" needs a call of that tool that did not succeed; "found"/"none" need a
    successful call of that tool
  - every plan step is either executed (with the tool the plan names) or skipped,
    exactly once; analyst_review steps can only be skipped (human-only)
No severity, verdict or recommendation is accepted (the schema has no field for them).
"""
from __future__ import annotations

from soc_agent.schemas import load_schema, load_tool_schema
from soc_agent.tools.base import RunContext, ToolRejection, ToolSpec

MAX_LOG_ATTEMPTS = 3


def evidence_log_problems(log: dict, ctx: RunContext) -> list[str]:
    """Run-level checks (the wrapper has already applied the full schema)."""
    issues: list[str] = []
    plan_steps = {s["step"]: s["tool"] for s in (ctx.plan or {}).get("steps", []) if isinstance(s, dict)}
    calls: dict[str, set[str]] = {}
    for c in ctx.tool_calls:
        calls.setdefault(c["tool"], set()).add(c["status"])
    seen: dict[int, str] = {}

    for e in log["executed_steps"]:
        n, tool, refs = e["step"], e["tool"], e["evidence_refs"]
        where = f"executed step {n}"
        if n in seen:
            issues.append(f"{where}: step {n} appears more than once (already {seen[n]})")
        seen[n] = "executed"
        if n not in plan_steps:
            issues.append(f"{where}: the plan has no step {n}")
        elif plan_steps[n] != tool:
            issues.append(f"{where}: the plan uses {plan_steps[n]} for step {n}, not {tool}")
        statuses = calls.get(tool, set())
        if not statuses:
            issues.append(f"{where}: {tool} was never called in this run")
        elif e["outcome"] == "failed" and statuses <= {"ok"}:
            issues.append(f"{where}: outcome failed, but every {tool} call succeeded")
        elif e["outcome"] in ("found", "none") and "ok" not in statuses:
            issues.append(f"{where}: outcome {e['outcome']}, but no {tool} call succeeded (use failed)")
        if e["outcome"] == "found" and not refs:
            issues.append(f"{where}: outcome found needs at least one evidence_ref returned by {tool}")
        if e["outcome"] != "found" and refs:
            issues.append(f"{where}: outcome {e['outcome']} must not cite evidence_refs")
        for ref in refs:
            source = ctx.evidence_refs.get(ref)
            if source is None:
                issues.append(f"{where}: evidence_ref {ref!r} was not returned by any tool in this run")
            elif source != tool:
                issues.append(f"{where}: evidence_ref {ref!r} was returned by {source}, not by {tool}")

    for s in log["skipped_steps"]:
        n = s["step"]
        if n in seen:
            issues.append(f"skipped step {n}: step {n} is listed more than once (already {seen[n]})")
        seen[n] = "skipped"
        if n not in plan_steps:
            issues.append(f"skipped step {n}: the plan has no step {n}")
        elif plan_steps[n] != s["tool"]:
            issues.append(f"skipped step {n}: the plan uses {plan_steps[n]} for step {n}, not {s['tool']}")

    for n, tool in sorted(plan_steps.items()):
        if tool == "analyst_review" and seen.get(n) == "executed":
            issues.append(f"step {n}: analyst_review is human-only and must be listed under skipped_steps")
        if n not in seen:
            issues.append(f"plan step {n} ({tool}) is missing: list it under executed_steps or skipped_steps")
    return issues


def _submit_evidence_log(args: dict, ctx: RunContext) -> dict:
    if ctx.evidence_log is not None:
        raise ToolRejection("An evidence log was already accepted for this investigation. Do not submit again.")
    attempts = 1 + sum(1 for c in ctx.tool_calls if c["tool"] == SUBMIT_EVIDENCE_LOG.name)
    if attempts > MAX_LOG_ATTEMPTS:
        raise ToolRejection(f"Too many evidence log submissions (limit {MAX_LOG_ATTEMPTS}). Stop and report failure.")
    if issues := evidence_log_problems(args, ctx):
        raise ToolRejection("Evidence log rejected.", issues,
                            f"Fix exactly these problems and call submit_evidence_log again "
                            f"(attempt {attempts} of {MAX_LOG_ATTEMPTS}). Cite only evidence_ref strings "
                            "exactly as the tools returned them.")
    ctx.evidence_log = args
    return {"accepted": True, "message": "Evidence log stored. Reply with one short sentence; no conclusions."}


def _summarize(r: dict) -> str:
    return "evidence log accepted"


def _argument_schema() -> dict:
    # The evidence log itself is the argument object (top-level executed_steps / skipped_steps). In the first
    # live NVIDIA run, a single nested object argument {"evidence_log": {...}} was twice sent as a malformed
    # JSON string; models fill top-level arguments far more reliably. Validation is unchanged (full schema).
    return {k: v for k, v in load_schema("evidence_log").items() if k not in ("$id", "title")}


SUBMIT_EVIDENCE_LOG = ToolSpec(
    name="submit_evidence_log",
    description=("Submit the evidence log for this investigation (exactly once). Arguments: executed_steps = a "
                 "JSON array with one object per executed evidence step {step, tool, reason, outcome "
                 "(found|none|failed), evidence_refs (up to 20 exact refs returned by that step's tool; [] unless "
                 "found)}; skipped_steps = a JSON array of {step, tool, reason} for steps not run. analyst_review "
                 "steps go ONLY in skipped_steps. No severity, verdict or recommendations. If problems are "
                 "returned, fix exactly those and resubmit (3 attempts in total)."),
    parameters=_argument_schema(),      # full schema: the wrapper validates it; the model gets the simplified one
    handler=_submit_evidence_log,
    permission="write_internal",
    output_schema=load_tool_schema("submit_evidence_log", "output"),
    summarize=_summarize,
)
