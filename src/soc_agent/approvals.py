"""Day 4 analyst path: approve / reject / execute (SIMULATED) actions the agent requested, and close investigations.

This module is used ONLY by the analyst CLI (soc_agent actions ..., soc_agent close ...) and the token-protected
analyst API endpoints. It has no tool wrapper, is never registered with Hermes and is never imported by the tool
layer (soc_agent/tools/*; a test checks this), so the agent has no way to reach it.

Rules
  - the analyst name is required; it cannot be empty or name the agent ("agent", "hermes", "mock", "system", ...)
  - a reason / resolution note is required
  - one decision per action (decisions.action_id is UNIQUE, and only a "pending" action can be decided)
  - an action expires ACTION_TTL (24 h) after it was requested: it can then no longer be approved or executed
  - only an approved, non-expired action of an open investigation can be executed; execution is SIMULATED: it
    records what WOULD happen (simulated_actions table + data/simulated_actions.log) and touches no system;
    executing again returns the first simulation (idempotent)
  - an investigation is closed only by an analyst, with a resolution note, and not while actions still await
    a decision
Every decision, simulation and status change is written to the append-only, hash-chained audit tables.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from soc_agent.store import (AWAITING_APPROVAL, CLOSED, UNDER_INVESTIGATION, Store, StoreError, parse_time,
                             request_digest)

# a name containing one of these words names the agent / automation ("Hermes Agent", "mock-bot", ...)
RESERVED_WORDS = {"agent", "hermes", "mock", "system", "assistant", "llm", "bot", "socagent", "nvidia", "nemotron",
                  "claude", "gpt", "automation"}
# these only as the whole name ("AI", "model"), so real names such as "Ai Tanaka" or "SOC Lead" stay valid
RESERVED_NAMES = RESERVED_WORDS | {"ai", "model", "auto", "soc", "llmagent", "aiagent"}
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9._ '-]{0,63}$")
SIMULATED_EFFECT = {
    "block_ip": "SIMULATED - would add a perimeter firewall rule denying all traffic to and from {target}. "
                "No firewall or network device was contacted.",
    "disable_account": "SIMULATED - would disable account {target} in the directory and end its active sessions. "
                       "No directory or host was contacted.",
    "isolate_host": "SIMULATED - would move host {target} to the quarantine network (EDR isolation), keeping the "
                    "SOC's forensic access. No host or EDR was contacted.",
}


class ApprovalError(RuntimeError):
    """The analyst operation is not allowed (the message says why)."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="milliseconds")


def check_analyst(name: str | None) -> str:
    """The analyst name, stripped. Refuses empty names and names of the agent / automation."""
    n = (name or "").strip()
    if not n:
        raise ApprovalError("an analyst name is required (--analyst NAME)")
    if not _NAME.fullmatch(n):
        raise ApprovalError(f"invalid analyst name {n!r}: letters, digits, '.', '_', '-', ' ' (max 64), starting "
                            "with a letter")
    tokens = {t for t in re.split(r"[^a-z]+", n.lower()) if t}          # digits split too: "Hermes2" -> hermes
    squashed = re.sub(r"[^a-z]", "", n.lower())
    if tokens & RESERVED_WORDS or squashed in RESERVED_NAMES or \
            any(squashed.startswith(w) or squashed.endswith(w) for w in RESERVED_WORDS if len(w) >= 4):
        raise ApprovalError(f"{n!r} is not a human analyst: the agent / automation can never approve, reject, "
                            "execute or close")
    return n


def _check_text(text: str | None, what: str, minimum: int = 5) -> str:
    t = (text or "").strip()
    if len(t) < minimum:
        raise ApprovalError(f"a {what} is required (at least {minimum} characters)")
    if len(t) > 2000:
        raise ApprovalError(f"the {what} is too long (max 2000 characters)")
    return t


def _expired(action: dict, now: datetime) -> bool:
    return now >= parse_time(action["expires_at"])


def _mark_expired(store: Store, action_id: str, now: datetime) -> None:
    """Expire the action (recorded as a chained action_events row, by system); if nothing awaits a decision any
    more, the investigation leaves Awaiting Approval (recorded in status_history, by system)."""
    with store.tx() as conn:
        row = conn.execute("SELECT investigation_id, status, expires_at FROM pending_actions WHERE id = ?",
                           (action_id,)).fetchone()
        if row["status"] not in ("pending", "approved"):
            return                                          # decided / expired meanwhile by another process
        conn.execute("UPDATE pending_actions SET status = 'expired', updated_at = ? WHERE id = ?",
                     (_iso(now), action_id))
        store.append_chained(conn, "action_events", {
            "action_id": action_id, "investigation_id": row["investigation_id"], "event": "expired",
            "from_status": row["status"], "by": "system",
            "reason": f"not {'executed' if row['status'] == 'approved' else 'decided'} before it expired at "
                      f"{row['expires_at']} (24 h after the request)", "at": _iso(now)})
        left = conn.execute("SELECT COUNT(*) AS n FROM pending_actions WHERE investigation_id = ? AND status = "
                            "'pending'", (row["investigation_id"],)).fetchone()["n"]
        if left == 0:
            store.set_status(row["investigation_id"], UNDER_INVESTIGATION, "system",
                             f"no actions awaiting approval ({action_id} expired unanswered after 24 h)", conn=conn,
                             if_from={AWAITING_APPROVAL})


def expire_overdue(store: Store, investigation_id: str | None = None, now: datetime | None = None) -> list[str]:
    """Mark every pending / approved action past its expiry as expired. Returns their ids."""
    now = now or _now()
    out = []
    for a in store.actions(investigation_id):
        if a["status"] in ("pending", "approved") and _expired(a, now):
            _mark_expired(store, a["id"], now)
            out.append(a["id"])
    return out


def list_actions(store: Store, investigation_id: str | None = None, now: datetime | None = None) -> list[dict]:
    """Actions with their decision / simulation; pending or approved actions past their expiry show as expired."""
    expire_overdue(store, investigation_id, now)
    decisions = {d["action_id"]: d for d in store.decisions(investigation_id)}
    sims = {s["action_id"]: s for s in store.simulated(investigation_id)}
    out = []
    for a in store.actions(investigation_id):
        d, s = decisions.get(a["id"]), sims.get(a["id"])
        out.append({**a, "decision": {k: d[k] for k in ("decision", "analyst", "reason", "decided_at")} if d else None,
                    "simulated_execution": {k: s[k] for k in ("executed_by", "executed_at", "simulated_effect")}
                    if s else None})
    return out


def _decide(store: Store, action_id: str, decision: str, analyst: str, reason: str,
            now: datetime | None = None) -> dict:
    analyst, reason, now = check_analyst(analyst), _check_text(reason, "reason"), now or _now()
    action = store.action(action_id)
    if action is None:
        raise ApprovalError(f"no action {action_id}")
    if action["status"] == "pending" and _expired(action, now):
        _mark_expired(store, action_id, now)
        raise ApprovalError(f"{action_id} expired at {action['expires_at']} (24 h after the request); it can no "
                            "longer be decided. Re-run the investigation for a fresh request.")
    with store.tx() as conn:
        row = conn.execute("SELECT status, investigation_id FROM pending_actions WHERE id = ?", (action_id,)).fetchone()
        inv = conn.execute("SELECT status FROM investigations WHERE id = ?", (row["investigation_id"],)).fetchone()
        if inv["status"] == CLOSED:
            raise ApprovalError(f"investigation {row['investigation_id']} is closed")
        prior = conn.execute("SELECT decision, analyst FROM decisions WHERE action_id = ?", (action_id,)).fetchone()
        if prior or row["status"] != "pending":
            who = f" ({prior['decision']} by {prior['analyst']})" if prior else ""
            raise ApprovalError(f"{action_id} is {row['status']}{who}: only one decision per action")
        t = _iso(now)
        # the decision is bound to exactly this request (type, target, reason, refs, ...): see execute()
        store.append_chained(conn, "decisions", {
            "action_id": action_id, "investigation_id": row["investigation_id"], "decision": decision,
            "analyst": analyst, "reason": reason, "decided_at": t, "action_type": action["action_type"],
            "target": action["target"], "request_digest": request_digest(action)})
        conn.execute("UPDATE pending_actions SET status = ?, updated_at = ? WHERE id = ?", (decision, t, action_id))
        left = conn.execute("SELECT COUNT(*) AS n FROM pending_actions WHERE investigation_id = ? AND status = "
                            "'pending'", (row["investigation_id"],)).fetchone()["n"]
        if left == 0:
            store.set_status(row["investigation_id"], UNDER_INVESTIGATION, f"analyst:{analyst}",
                             f"no actions awaiting approval (last: {action_id} {decision})", conn=conn,
                             if_from={AWAITING_APPROVAL})
    return store.action(action_id)


def approve(store: Store, action_id: str, analyst: str, reason: str, now: datetime | None = None) -> dict:
    return _decide(store, action_id, "approved", analyst, reason, now)


def reject(store: Store, action_id: str, analyst: str, reason: str, now: datetime | None = None) -> dict:
    return _decide(store, action_id, "rejected", analyst, reason, now)


def execute(store: Store, action_id: str, log_path: Path, analyst: str | None = None,
            now: datetime | None = None) -> dict:
    """SIMULATE an approved action. Returns {action, simulation, already_executed}. Nothing real is changed."""
    now = now or _now()
    action = store.action(action_id)
    if action is None:
        raise ApprovalError(f"no action {action_id}")
    done = next((s for s in store.simulated(action["investigation_id"]) if s["action_id"] == action_id), None)
    if done:                                                   # idempotent: never simulated twice
        return {"action": action, "simulation": done, "already_executed": True}
    if action["status"] == "pending":
        raise ApprovalError(f"{action_id} is pending: an analyst must approve it first "
                            f"(soc_agent actions approve {action_id} --analyst NAME --reason \"...\")")
    if action["status"] != "approved":
        raise ApprovalError(f"{action_id} is {action['status']}: only an approved action can be executed")
    if _expired(action, now):
        _mark_expired(store, action_id, now)
        raise ApprovalError(f"{action_id} expired at {action['expires_at']}; it can no longer be executed")
    decision = next((d for d in store.decisions(action["investigation_id"]) if d["action_id"] == action_id), None)
    if decision is None or decision["decision"] != "approved":   # the status column alone is never trusted
        raise ApprovalError(f"{action_id} has no analyst approval in the audit trail (decision: "
                            f"{decision['decision'] if decision else 'none'}); refusing to execute. Run verify-audit.")
    if (decision.get("request_digest") and decision["request_digest"] != request_digest(action)) or \
            (decision.get("target") and (decision["action_type"], decision["target"]) !=
             (action["action_type"], action["target"])):
        raise ApprovalError(f"{action_id} was changed after it was approved (approved: {decision.get('action_type')} "
                            f"{decision.get('target')}); refusing to execute. Run verify-audit.")
    # who executes: the named analyst; without a name the record says so (never credited to the approver)
    executor = check_analyst(analyst) if analyst else f"(not named; approved by {decision['analyst']})"
    with store.tx() as conn:
        row = conn.execute("SELECT status FROM pending_actions WHERE id = ?", (action_id,)).fetchone()
        inv = conn.execute("SELECT status FROM investigations WHERE id = ?", (action["investigation_id"],)).fetchone()
        prior = conn.execute("SELECT * FROM simulated_actions WHERE action_id = ?", (action_id,)).fetchone()
        if prior:                                             # a concurrent execute won the race: idempotent
            return {"action": store.action(action_id), "simulation": dict(prior), "already_executed": True}
        if inv["status"] == CLOSED:
            raise ApprovalError(f"investigation {action['investigation_id']} is closed")
        if row["status"] != "approved":
            raise ApprovalError(f"{action_id} is {row['status']}")
        sim = store.append_chained(conn, "simulated_actions", {
            "action_id": action_id, "investigation_id": action["investigation_id"],
            "action_type": action["action_type"], "target": action["target"], "executed_by": executor,
            "simulated_effect": SIMULATED_EFFECT[action["action_type"]].format(target=action["target"]),
            "executed_at": _iso(now)})
        conn.execute("UPDATE pending_actions SET status = 'executed', updated_at = ? WHERE id = ?",
                     (_iso(now), action_id))
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"simulated": True, "action_id": action_id, "investigation_id": action["investigation_id"],
                             "action_type": action["action_type"], "target": action["target"],
                             "approved_by": decision["analyst"], "executed_by": executor,
                             "executed_at": sim["executed_at"], "effect": sim["simulated_effect"]},
                            ensure_ascii=False) + "\n")
    return {"action": store.action(action_id), "simulation": sim, "already_executed": False}


def close(store: Store, investigation_id: str, analyst: str, resolution: str) -> dict:
    """Close the investigation. Approved actions that were not executed stay approved and can no longer run
    (the result lists them under not_executed)."""
    analyst, resolution = check_analyst(analyst), _check_text(resolution, "resolution note", 10)
    inv = store.investigation(investigation_id)
    if inv is None:
        raise ApprovalError(f"no investigation {investigation_id}")
    if inv["status"] == CLOSED:
        raise ApprovalError(f"investigation {investigation_id} is already closed")
    expire_overdue(store, investigation_id)               # an overdue request no longer blocks closing
    with store.tx() as conn:
        # checked inside the write transaction, so a request_action cannot slip in between check and close
        pending = [r["id"] for r in conn.execute("SELECT id FROM pending_actions WHERE investigation_id = ? AND "
                                                 "status = 'pending'", (investigation_id,))]
        if pending:
            raise ApprovalError(f"{len(pending)} action(s) still await a decision ({', '.join(pending)}): approve "
                                "or reject them before closing")
        conn.execute("UPDATE investigations SET resolution = ?, closed_by = ? WHERE id = ?",
                     (resolution, analyst, investigation_id))
        try:
            store.set_status(investigation_id, CLOSED, f"analyst:{analyst}", resolution, conn=conn)
        except StoreError as e:
            raise ApprovalError(str(e)) from None
    return {**store.investigation(investigation_id),
            "not_executed": [a["id"] for a in store.actions(investigation_id, status="approved")]}
