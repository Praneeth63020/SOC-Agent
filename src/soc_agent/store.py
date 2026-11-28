"""Investigation history and audit trail (Day 4): one SQLite database, stdlib sqlite3 only.

    state/soc.db   (git-ignored; SOC_DB_PATH overrides)

Tables
  investigations    one row per investigation: alert, status, severity, confidence, provider, model, mock, synthetic
  phases            one row per phase run (plan | investigate | assess | report): the task prompt (system prompt +
                    user message), the tools Hermes exposed, start / finish, status, Hermes stats, error, output
  tool_calls        every tool call of every phase, in call order, including calls Hermes refused itself:
                    tool, permission, arguments, status, result (size-capped + truncated flag), the reason the
                    agent gave, timestamps, duration
  evidence          ref -> tool, entities (account, host, IPs) and a short excerpt of the full tool result; what
                    the report's evidence appendix and request_action's target check read
  reports           incident report versions (JSON + Markdown)
  pending_actions   containment the agent REQUESTED (request_action); only an analyst can decide (approvals.py)
  decisions         the analyst's approve / reject decision, one per action
  simulated_actions what an approved action WOULD have done (nothing real is ever changed)
  status_history    every investigation status transition: from, to, by, reason, at
  action_events     system events on a requested action that no analyst decided (expiry), one row per action

Append-only: triggers ABORT any UPDATE or DELETE on phases, tool_calls, evidence, reports, decisions,
simulated_actions and status_history. Only investigations (current status, severity, ...) and pending_actions
(current status) change, and every such change is also written to status_history / decisions.

Tamper evidence: every phases, reports, tool_calls, decisions, simulated_actions, status_history and
action_events row stores prev_hash (the row_hash of the previous row of the same table, or 64 zeros) and
row_hash = sha256 over the canonical JSON of the row (all columns except id and row_hash, prev_hash included).
verify_audit() recomputes every chain and reports the first broken row, and checks that every action's state
agrees with the chained records (an executed action has an approved decision, an expired one an expiry event,
...). phases and reports were chained in Day 5: rows written before that (NULL row_hash) are accepted only as a
prefix of the table; an unhashed row after the first hashed one is reported. (Residual risk, see
docs/security.md: the chain head is not anchored outside the DB, so someone with write access to the file can
append correctly hashed rows, rewrite a whole chain or cut its tail; evidence rows are append-only, not chained.)
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

OPEN, UNDER_INVESTIGATION, AWAITING_APPROVAL, CLOSED = "Open", "Under Investigation", "Awaiting Approval", "Closed"
STATUSES = (OPEN, UNDER_INVESTIGATION, AWAITING_APPROVAL, CLOSED)
TRANSITIONS = {                      # from -> allowed targets
    None: {OPEN},
    OPEN: {UNDER_INVESTIGATION, CLOSED},
    UNDER_INVESTIGATION: {AWAITING_APPROVAL, CLOSED},
    AWAITING_APPROVAL: {UNDER_INVESTIGATION, CLOSED},
    CLOSED: set(),
}
PHASES = ("plan", "investigate", "assess", "report")
CALL_STATUSES = ("ok", "rejected", "denied", "error", "timeout", "refused_by_hermes", "invalid_json_rejected_by_hermes")
ACTION_TYPES = ("block_ip", "disable_account", "isolate_host")
ACTION_STATUSES = ("pending", "approved", "rejected", "executed", "expired")
ACTION_TTL = timedelta(hours=24)
GENESIS = "0" * 64
RESULT_MAX_CHARS = 20_000            # result_json larger than this is stored as a preview (result_truncated = 1)
EXCERPT_MAX = 240

HASHED_TABLES = ("phases", "reports", "tool_calls", "decisions", "simulated_actions", "status_history",
                 "action_events")
CHAINED_LATER = ("phases", "reports")     # chained since Day 5: older rows (NULL row_hash) only as a table prefix
APPEND_ONLY_TABLES = ("phases", "tool_calls", "evidence", "reports", "decisions", "simulated_actions",
                      "status_history", "action_events")

# Hashed tables have columns WITHOUT a declared type (except id), so SQLite returns every value exactly as it was
# written (an int stays an int, a float a float) and the hash recomputed from the stored row matches.
_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    alert_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ({", ".join(repr(s) for s in STATUSES)})),
    severity TEXT, confidence TEXT,
    provider TEXT, model TEXT, mock INTEGER NOT NULL DEFAULT 0, synthetic INTEGER NOT NULL DEFAULT 0,
    resolution TEXT, closed_by TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS phases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    phase TEXT NOT NULL CHECK (phase IN ({", ".join(repr(p) for p in PHASES)})),
    task_system_prompt TEXT, task_user_message TEXT, exposed_tools_json TEXT,
    started_at TEXT, finished_at TEXT, status TEXT, hermes_json TEXT, error TEXT, warnings_json TEXT,
    mock_scenario TEXT, output_json TEXT, run_record TEXT,
    prev_hash TEXT, row_hash TEXT
);
CREATE TABLE IF NOT EXISTS tool_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id NOT NULL, phase NOT NULL, phase_id NOT NULL, seq NOT NULL, tool NOT NULL, permission,
    arguments_json, status NOT NULL CHECK (status IN ({", ".join(repr(s) for s in CALL_STATUSES)})),
    result_json, result_truncated, result_summary, evidence_refs_json, fault_injected, reason,
    started_at, finished_at, duration_ms,
    prev_hash NOT NULL, row_hash NOT NULL
);
CREATE INDEX IF NOT EXISTS tool_calls_inv ON tool_calls(investigation_id);
CREATE TABLE IF NOT EXISTS evidence (
    investigation_id TEXT NOT NULL, ref TEXT NOT NULL, tool TEXT NOT NULL, phase TEXT NOT NULL,
    event_type TEXT, time TEXT, account TEXT, host TEXT, ips_json TEXT, excerpt TEXT,
    PRIMARY KEY (investigation_id, ref)
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    version INTEGER NOT NULL, json TEXT NOT NULL, markdown TEXT NOT NULL, created_at TEXT NOT NULL,
    prev_hash TEXT, row_hash TEXT,
    UNIQUE (investigation_id, version)
);
CREATE TABLE IF NOT EXISTS pending_actions (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    action_type TEXT NOT NULL CHECK (action_type IN ({", ".join(repr(a) for a in ACTION_TYPES)})),
    target TEXT NOT NULL, reason TEXT NOT NULL, evidence_refs_json TEXT NOT NULL, expected_impact TEXT NOT NULL,
    requested_by TEXT NOT NULL, phase TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ({", ".join(repr(s) for s in ACTION_STATUSES)})),
    created_at TEXT NOT NULL, expires_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id NOT NULL UNIQUE, investigation_id NOT NULL,
    decision NOT NULL CHECK (decision IN ('approved', 'rejected')),
    analyst NOT NULL, reason NOT NULL, decided_at NOT NULL,
    prev_hash NOT NULL, row_hash NOT NULL,
    action_type, target, request_digest
);
CREATE TABLE IF NOT EXISTS simulated_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id NOT NULL UNIQUE, investigation_id NOT NULL, action_type NOT NULL, target NOT NULL,
    executed_by NOT NULL, simulated_effect NOT NULL, executed_at NOT NULL,
    prev_hash NOT NULL, row_hash NOT NULL
);
CREATE TABLE IF NOT EXISTS status_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id NOT NULL, from_status, to_status NOT NULL, by NOT NULL, reason, at NOT NULL,
    prev_hash NOT NULL, row_hash NOT NULL
);
CREATE TABLE IF NOT EXISTS action_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id NOT NULL, investigation_id NOT NULL, event NOT NULL CHECK (event IN ('expired')),
    from_status NOT NULL, by NOT NULL, reason NOT NULL, at NOT NULL,
    prev_hash NOT NULL, row_hash NOT NULL
);
""" + "".join(f"""
CREATE TRIGGER IF NOT EXISTS {t}_no_update BEFORE UPDATE ON {t}
BEGIN SELECT RAISE(ABORT, 'audit table {t} is append-only: UPDATE is not allowed'); END;
CREATE TRIGGER IF NOT EXISTS {t}_no_delete BEFORE DELETE ON {t}
BEGIN SELECT RAISE(ABORT, 'audit table {t} is append-only: DELETE is not allowed'); END;
""" for t in APPEND_ONLY_TABLES)


class StoreError(RuntimeError):
    """A rule of the store was broken (unknown investigation, forbidden status transition, ...)."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def parse_time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def clean_text(text: str) -> str:
    """UTF-8-safe text: a lone surrogate (valid in JSON, e.g. "\\ud800", but not encodable) becomes '?'."""
    return text.encode("utf-8", "replace").decode("utf-8")


def _dumps(value: Any) -> str | None:
    return None if value is None else clean_text(json.dumps(value, ensure_ascii=False, default=str))


def _loads(text: str | None) -> Any:
    return None if text in (None, "") else json.loads(text)


def canonical(row: dict) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


# columns added after the first release: NULL in older rows, so they are left out of those rows' hash
LATE_COLUMNS = {"decisions": ("action_type", "target", "request_digest")}


def row_hash(table: str, row: dict) -> str:
    """sha256 over the canonical JSON of the row (without id / row_hash) plus the table name."""
    late = LATE_COLUMNS.get(table, ())
    body = {k: v for k, v in row.items() if k not in ("id", "row_hash") and not (k in late and v is None)}
    return hashlib.sha256(canonical({"table": table, **body}).encode("utf-8")).hexdigest()


REQUEST_FIELDS = ("id", "investigation_id", "action_type", "target", "reason", "evidence_refs", "expected_impact",
                  "requested_by", "phase", "created_at", "expires_at")


def request_digest(action: dict) -> str:
    """sha256 of what the agent requested (not its status). Stored with the analyst's decision, so an approval
    is bound to exactly that request: execute and verify-audit refuse / report a request changed afterwards."""
    return hashlib.sha256(canonical({k: action.get(k) for k in REQUEST_FIELDS}).encode("utf-8")).hexdigest()


def _capped(value: Any, limit: int = RESULT_MAX_CHARS) -> tuple[str | None, int]:
    if value is None:
        return None, 0
    text = _dumps(value)
    if len(text) <= limit:
        return text, 0
    return _dumps({"_truncated": True, "original_chars": len(text), "preview": text[:limit]}), 1


class Store:
    """All database access. Every operation opens its own short connection (safe across Hermes's threads)."""

    _init_lock = threading.Lock()

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._init_lock, self._connect() as conn:
            for table in CHAINED_LATER:                         # migrate a database from before Day 5
                have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
                for col in ("prev_hash", "row_hash"):
                    if have and col not in have:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")
            conn.executescript(_SCHEMA)
            have = {r["name"] for r in conn.execute("PRAGMA table_info(decisions)")}
            for col in LATE_COLUMNS["decisions"]:              # migrate a database from before these columns
                if col not in have:
                    conn.execute(f"ALTER TABLE decisions ADD COLUMN {col}")
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(tool_calls)")}
            if missing := {"phase_id", "reason", "prev_hash", "row_hash"} - cols:
                raise StoreError(f"{self.path} has an older schema (tool_calls lacks {sorted(missing)}); move it "
                                 "aside (it is git-ignored) and run again")

    # ------------------------------------------------------------------ plumbing
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """One write transaction (BEGIN IMMEDIATE: hash-chain inserts are serialized)."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def query(self, sql: str, params: tuple | list = ()) -> list[dict]:
        conn = self._connect()
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    def append_chained(self, conn: sqlite3.Connection, table: str, row: dict) -> dict:
        """Insert `row` into a hash-chained table inside the caller's transaction."""
        if table not in HASHED_TABLES:
            raise ValueError(f"{table} is not a hash-chained table")
        last = conn.execute(f"SELECT row_hash FROM {table} WHERE row_hash IS NOT NULL ORDER BY id DESC "
                            "LIMIT 1").fetchone()
        row = {k: clean_text(v) if isinstance(v, str) else v for k, v in row.items()}
        row["prev_hash"] = last["row_hash"] if last else GENESIS
        row["row_hash"] = row_hash(table, row)
        cols = list(row)
        cur = conn.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                           [row[c] for c in cols])
        return {"id": cur.lastrowid, **row}

    # ------------------------------------------------------------ investigations
    def ensure_investigation(self, investigation_id: str, alert: dict, provider: str | None, model: str | None,
                             mock: bool, by: str = "system") -> bool:
        """Create the investigation (status Open) if it does not exist yet. Returns True if created."""
        with self.tx() as conn:
            if conn.execute("SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)).fetchone():
                return False
            t = now()
            conn.execute("INSERT INTO investigations (id, alert_id, alert_json, status, provider, model, mock, "
                         "synthetic, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (investigation_id, alert["alert_id"],
                          _dumps({k: v for k, v in alert.items() if k != "raw"}), OPEN, provider, model,
                          int(bool(mock)), int(bool(alert.get("synthetic"))), t, t))
            self.append_chained(conn, "status_history", {
                "investigation_id": investigation_id, "from_status": None, "to_status": OPEN, "by": by,
                "reason": f"alert {alert['alert_id']} accepted", "at": t})
            return True

    def set_status(self, investigation_id: str, to: str, by: str, reason: str,
                   conn: sqlite3.Connection | None = None, if_from: set[str] | None = None) -> bool:
        """Move the investigation to `to` (recorded in status_history). Returns False if it already is there,
        or if `if_from` is given and the current status is not in it. Forbidden transitions raise StoreError."""
        if conn is None:
            with self.tx() as c:
                return self.set_status(investigation_id, to, by, reason, conn=c, if_from=if_from)
        row = conn.execute("SELECT status FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        if row is None:
            raise StoreError(f"no investigation {investigation_id}")
        frm = row["status"]
        if frm == to or (if_from is not None and frm not in if_from):
            return False
        if to not in TRANSITIONS.get(frm, set()):
            raise StoreError(f"investigation {investigation_id}: status {frm} -> {to} is not allowed")
        if to == CLOSED and not by.startswith("analyst:"):
            raise StoreError("only an analyst can close an investigation")
        t = now()
        conn.execute("UPDATE investigations SET status = ?, updated_at = ? WHERE id = ?", (to, t, investigation_id))
        self.append_chained(conn, "status_history", {"investigation_id": investigation_id, "from_status": frm,
                                                     "to_status": to, "by": by, "reason": reason, "at": t})
        return True

    def update_investigation(self, investigation_id: str, **fields: Any) -> None:
        allowed = {"severity", "confidence", "resolution", "closed_by"}
        if bad := set(fields) - allowed:
            raise ValueError(f"cannot update {sorted(bad)}")
        if not fields:
            return
        sets = ", ".join(f"{k} = ?" for k in fields)
        with self.tx() as conn:
            conn.execute(f"UPDATE investigations SET {sets}, updated_at = ? WHERE id = ?",
                         [*fields.values(), now(), investigation_id])

    def investigation(self, investigation_id: str) -> dict | None:
        rows = self.query("SELECT * FROM investigations WHERE id = ?", (investigation_id,))
        if not rows:
            return None
        r = rows[0]
        r["alert"] = _loads(r.pop("alert_json"))
        r["mock"], r["synthetic"] = bool(r["mock"]), bool(r["synthetic"])
        return r

    def investigations(self, limit: int = 20) -> list[dict]:
        rows = self.query("SELECT id, alert_id, status, severity, confidence, provider, model, mock, synthetic, "
                          "created_at, updated_at, (SELECT COUNT(*) FROM pending_actions p WHERE "
                          "p.investigation_id = i.id AND p.status = 'pending') AS pending_actions "
                          "FROM investigations i ORDER BY created_at DESC, i.rowid DESC LIMIT ?", (limit,))
        for r in rows:
            r["mock"], r["synthetic"] = bool(r["mock"]), bool(r["synthetic"])
        return rows

    # ------------------------------------------------------------------- phases
    def record_phase(self, investigation_id: str, phase: str, *, system_prompt: str | None, user_message: str | None,
                     exposed_tools: list[str], started_at: str, finished_at: str, status: str,
                     hermes: dict | None, error: str | None, warnings: list[str], calls: list[dict],
                     evidence_results: list[dict] | None = None, output: Any = None,
                     mock_scenario: str | None = None, run_record: str | None = None) -> int:
        """One phase run: its task, its tool calls (in call order, see audit_sequence) and the evidence its
        successful read calls returned. One transaction: all of it, or nothing."""
        if phase not in PHASES:
            raise ValueError(f"unknown phase {phase!r}")
        with self.tx() as conn:
            phase_id = self.append_chained(conn, "phases", {
                "investigation_id": investigation_id, "phase": phase, "task_system_prompt": system_prompt,
                "task_user_message": user_message, "exposed_tools_json": _dumps(exposed_tools),
                "started_at": started_at, "finished_at": finished_at, "status": status, "hermes_json": _dumps(hermes),
                "error": error, "warnings_json": _dumps(warnings), "mock_scenario": mock_scenario,
                "output_json": _dumps(output), "run_record": run_record})["id"]
            for i, c in enumerate(calls, 1):
                result, cut = _capped(c.get("result"))
                self.append_chained(conn, "tool_calls", {
                    "investigation_id": investigation_id, "phase": phase, "phase_id": phase_id, "seq": i,
                    "tool": c["tool"],
                    "permission": c.get("permission"), "arguments_json": _capped(c.get("arguments"))[0],
                    "status": c["status"], "result_json": result,
                    "result_truncated": int(bool(c.get("result_truncated")) or bool(cut)),
                    "result_summary": c.get("result_summary"), "evidence_refs_json": _dumps(c.get("evidence_refs") or []),
                    "fault_injected": c.get("fault_injected"), "reason": c.get("reason"),
                    "started_at": c.get("started_at"), "finished_at": c.get("finished_at"),
                    "duration_ms": None if c.get("duration_ms") is None else float(c["duration_ms"])})
            for ref, ev in evidence_index(evidence_results or []).items():
                conn.execute("INSERT OR IGNORE INTO evidence (investigation_id, ref, tool, phase, event_type, time, "
                             "account, host, ips_json, excerpt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                             (investigation_id, ref, ev["tool"], phase, ev.get("event_type"), ev.get("time"),
                              ev.get("account"), ev.get("host"), _dumps(ev.get("ips") or []), ev["excerpt"]))
            return phase_id

    def phases(self, investigation_id: str) -> list[dict]:
        rows = self.query("SELECT * FROM phases WHERE investigation_id = ? ORDER BY id", (investigation_id,))
        for r in rows:
            for k in ("exposed_tools_json", "hermes_json", "warnings_json", "output_json"):
                r[k.removesuffix("_json")] = _loads(r.pop(k))
        return rows

    def latest_output(self, investigation_id: str, phase: str, status: str | None = None) -> dict | None:
        sql = "SELECT output_json FROM phases WHERE investigation_id = ? AND phase = ?"
        params: list = [investigation_id, phase]
        if status:
            sql += " AND status = ?"
            params.append(status)
        rows = self.query(sql + " ORDER BY id DESC LIMIT 1", params)
        return _loads(rows[0]["output_json"]) if rows else None

    def tool_calls(self, investigation_id: str) -> list[dict]:
        rows = self.query("SELECT * FROM tool_calls WHERE investigation_id = ? ORDER BY id", (investigation_id,))
        for r in rows:
            for k in ("arguments_json", "result_json", "evidence_refs_json"):
                r[k.removesuffix("_json")] = _loads(r.pop(k))
            r["result_truncated"] = bool(r["result_truncated"])
        return rows

    def evidence(self, investigation_id: str) -> dict[str, dict]:
        rows = self.query("SELECT * FROM evidence WHERE investigation_id = ? ORDER BY rowid", (investigation_id,))
        return {r["ref"]: {**{k: r[k] for k in ("tool", "phase", "event_type", "time", "account", "host", "excerpt")},
                           "ips": _loads(r["ips_json"]) or []} for r in rows}

    # ------------------------------------------------------------------- reports
    def add_report(self, investigation_id: str, report: dict, markdown: str) -> int:
        """Store report["version"]; raises StoreError if that version exists already (a concurrent writer)."""
        version = report["version"]
        try:
            with self.tx() as conn:
                self.append_chained(conn, "reports", {"investigation_id": investigation_id, "version": version,
                                                      "json": _dumps(report), "markdown": clean_text(markdown),
                                                      "created_at": now()})
        except sqlite3.IntegrityError:
            raise StoreError(f"report version {version} of {investigation_id} exists already") from None
        return version

    def report(self, investigation_id: str, version: int | None = None) -> dict | None:
        sql = "SELECT * FROM reports WHERE investigation_id = ?"
        params: list = [investigation_id]
        if version is not None:
            sql += " AND version = ?"
            params.append(version)
        rows = self.query(sql + " ORDER BY version DESC LIMIT 1", params)
        if not rows:
            return None
        r = rows[0]
        return {"version": r["version"], "json": _loads(r["json"]), "markdown": r["markdown"],
                "created_at": r["created_at"]}

    def report_versions(self, investigation_id: str) -> list[dict]:
        return self.query("SELECT version, created_at FROM reports WHERE investigation_id = ? ORDER BY version",
                          (investigation_id,))

    # ------------------------------------------------------------ pending actions
    def add_pending_action(self, investigation_id: str, action_type: str, target: str, reason: str,
                           evidence_refs: list[str], expected_impact: str, requested_by: str, phase: str) -> dict:
        """A REQUEST for a disruptive action (status pending). Moves the investigation to Awaiting Approval.
        Duplicates (same type + target still pending or approved) raise StoreError."""
        if action_type not in ACTION_TYPES:
            raise StoreError(f"unknown action type {action_type!r}")
        with self.tx() as conn:
            inv = conn.execute("SELECT status FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
            if inv is None or inv["status"] == CLOSED:
                raise StoreError(f"investigation {investigation_id} is {'closed' if inv else 'unknown'}; "
                                 "no new action requests")
            dup = conn.execute("SELECT id, status FROM pending_actions WHERE investigation_id = ? AND action_type = ? "
                               "AND lower(target) = lower(?) AND status IN ('pending', 'approved') AND expires_at > ?",
                               (investigation_id, action_type, target, now())).fetchone()
            if dup:
                raise StoreError(f"{action_type} {target} was already requested ({dup['id']}, {dup['status']})")
            t = datetime.now(timezone.utc)
            action_id = f"ACT-{uuid.uuid4().hex[:10].upper()}"
            row = {"id": action_id, "investigation_id": investigation_id, "action_type": action_type,
                   "target": target, "reason": reason, "evidence_refs_json": _dumps(evidence_refs),
                   "expected_impact": expected_impact, "requested_by": requested_by, "phase": phase,
                   "status": "pending", "created_at": t.isoformat(timespec="milliseconds"),
                   "expires_at": (t + ACTION_TTL).isoformat(timespec="milliseconds"),
                   "updated_at": t.isoformat(timespec="milliseconds")}
            conn.execute(f"INSERT INTO pending_actions ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                         list(row.values()))
            self.set_status(investigation_id, AWAITING_APPROVAL, requested_by,
                            f"{action_type} {target} requested ({action_id}); waiting for an analyst decision",
                            conn=conn, if_from={UNDER_INVESTIGATION})
            return self._action_row(row)

    @staticmethod
    def _action_row(r: dict) -> dict:
        r = dict(r)
        r["evidence_refs"] = _loads(r.pop("evidence_refs_json"))
        return r

    def actions(self, investigation_id: str | None = None, status: str | None = None) -> list[dict]:
        sql, params = "SELECT * FROM pending_actions WHERE 1=1", []
        if investigation_id:
            sql += " AND investigation_id = ?"
            params.append(investigation_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        # rowid breaks created_at ties in insertion order (ids are random hex, so "id" would shuffle them)
        return [self._action_row(r) for r in self.query(sql + " ORDER BY created_at, rowid", params)]

    def action(self, action_id: str) -> dict | None:
        rows = self.query("SELECT * FROM pending_actions WHERE id = ?", (action_id,))
        return self._action_row(rows[0]) if rows else None

    # ----------------------------------------------------------- audit views
    def decisions(self, investigation_id: str | None = None) -> list[dict]:
        if investigation_id:
            return self.query("SELECT * FROM decisions WHERE investigation_id = ? ORDER BY id", (investigation_id,))
        return self.query("SELECT * FROM decisions ORDER BY id")

    def simulated(self, investigation_id: str | None = None) -> list[dict]:
        if investigation_id:
            return self.query("SELECT * FROM simulated_actions WHERE investigation_id = ? ORDER BY id",
                              (investigation_id,))
        return self.query("SELECT * FROM simulated_actions ORDER BY id")

    def status_history(self, investigation_id: str) -> list[dict]:
        return self.query("SELECT * FROM status_history WHERE investigation_id = ? ORDER BY id", (investigation_id,))

    def verify_audit(self) -> dict:
        """Recompute every hash chain. {ok, tables: {table: {rows, ok, first_broken: {id, problem} | None}}}"""
        out: dict[str, dict] = {}
        for table in HASHED_TABLES:
            rows = self.query(f"SELECT * FROM {table} ORDER BY id")
            prev, broken, legacy = GENESIS, None, 0
            for r in rows:
                if table in CHAINED_LATER and r["row_hash"] is None:
                    if prev != GENESIS:
                        broken = {"id": r["id"], "problem": "a row without a hash was added after the chain started "
                                                            "(inserted outside the application)"}
                        break
                    legacy += 1                                  # written before Day 5 chained this table
                    continue
                if r["prev_hash"] != prev:
                    broken = {"id": r["id"], "problem": "prev_hash does not match the previous row's row_hash "
                                                        "(a row was deleted, inserted or reordered)"}
                    break
                if row_hash(table, r) != r["row_hash"]:
                    broken = {"id": r["id"], "problem": "row_hash does not match the row's content (the row was "
                                                        "modified)"}
                    break
                prev = r["row_hash"]
            out[table] = {"rows": len(rows), "ok": broken is None, "first_broken": broken}
            if legacy:
                out[table]["unchained_legacy_rows"] = legacy
        # every decided request must still be exactly what the analyst decided on
        actions = {a["id"]: a for a in self.actions()}
        broken = None
        checked = 0
        for d in self.query("SELECT id, action_id, request_digest FROM decisions WHERE request_digest IS NOT NULL "
                            "ORDER BY id"):
            checked += 1
            a = actions.get(d["action_id"])
            if a is None or request_digest(a) != d["request_digest"]:
                broken = {"id": d["action_id"], "problem": "the action request differs from the one the analyst "
                                                           f"decided on (decision id {d['id']})"}
                break
        out["pending_actions"] = {"rows": checked, "ok": broken is None, "first_broken": broken}
        out["action_states"] = self._check_action_states(actions)
        return {"ok": all(t["ok"] for t in out.values()), "tables": out}

    def _check_action_states(self, actions: dict[str, dict]) -> dict:
        """Every action's current status (the one mutable column) must agree with the chained records: approved /
        executed <- an approved decision, rejected <- a rejected decision, expired <- an expiry event or an approved
        decision; every simulated execution <- an approved decision."""
        decisions = {d["action_id"]: d["decision"] for d in self.query("SELECT action_id, decision FROM decisions")}
        expired = {e["action_id"] for e in self.query("SELECT action_id FROM action_events WHERE event = 'expired'")}
        sims = {s["action_id"] for s in self.query("SELECT action_id FROM simulated_actions")}
        need = {"approved": "approved", "executed": "approved", "rejected": "rejected"}
        broken = None
        for a in actions.values():
            st, d = a["status"], decisions.get(a["id"])
            if (st in need and d != need[st]) or (st == "pending" and d) or \
                    (st == "expired" and a["id"] not in expired) or (a["id"] in sims and d != "approved") or \
                    (st == "executed" and a["id"] not in sims):
                broken = {"id": a["id"], "problem": f"status {st!r} does not match the audit trail (decision "
                                                    f"{d or 'none'}, expiry event "
                                                    f"{'yes' if a['id'] in expired else 'no'}, simulated "
                                                    f"{'yes' if a['id'] in sims else 'no'})"}
                break
        for sid in sorted(sims - set(actions)):
            broken = broken or {"id": sid, "problem": "a simulated execution for an unknown action"}
        return {"rows": len(actions), "ok": broken is None, "first_broken": broken}

    def action_events(self, investigation_id: str | None = None) -> list[dict]:
        if investigation_id:
            return self.query("SELECT * FROM action_events WHERE investigation_id = ? ORDER BY id",
                              (investigation_id,))
        return self.query("SELECT * FROM action_events ORDER BY id")

    def export(self, investigation_id: str) -> dict | None:
        inv = self.investigation(investigation_id)
        if inv is None:
            return None
        return {"investigation": inv, "status_history": self.status_history(investigation_id),
                "phases": self.phases(investigation_id), "tool_calls": self.tool_calls(investigation_id),
                "evidence": self.evidence(investigation_id), "pending_actions": self.actions(investigation_id),
                "decisions": self.decisions(investigation_id), "simulated_actions": self.simulated(investigation_id),
                "action_events": self.action_events(investigation_id),
                "report_versions": self.report_versions(investigation_id), "exported_at": now()}


# ---------------------------------------------------------------------- helpers
def audit_sequence(tool_calls: list[dict], messages: list | None, allowed: set[str], reply_prefixes: tuple) -> list[dict]:
    """The phase's tool calls in the order the model made them: calls our wrapper ran (tool_calls) interleaved
    with calls Hermes answered itself (a tool outside the toolset -> refused_by_hermes; arguments that are not
    valid JSON -> invalid_json_rejected_by_hermes), each with the text the model wrote alongside it (its reason).
    Hermes does not time the calls it refuses: they get the time of the call before them and no duration."""
    replies = {m.get("tool_call_id"): m.get("content") for m in messages or []
               if isinstance(m, dict) and m.get("role") == "tool"}
    pending = list(tool_calls)
    out: list[dict] = []
    last_time = None
    for m in messages or []:
        if not isinstance(m, dict) or m.get("role") != "assistant":
            continue
        text = (m.get("content") if isinstance(m.get("content"), str) else "") or ""
        reason = text.strip()[:500] or None
        for tc in m.get("tool_calls") or []:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") or {}
            name, reply = fn.get("name"), replies.get(tc.get("id"))
            if not name:
                continue
            refused = name not in allowed
            bad_json = not refused and isinstance(reply, str) and reply.startswith(reply_prefixes)
            if refused or bad_json:
                args = fn.get("arguments")
                try:
                    args = json.loads(args) if isinstance(args, str) else args
                except ValueError:
                    pass
                out.append({"tool": name, "permission": None, "arguments": args,
                            "status": "refused_by_hermes" if refused else "invalid_json_rejected_by_hermes",
                            "result": {"hermes_reply": reply}, "result_summary": f"never executed: {str(reply)[:200]}",
                            "evidence_refs": [], "reason": reason, "started_at": last_time, "finished_at": last_time,
                            "duration_ms": None})
                continue
            idx = next((i for i, c in enumerate(pending) if c["tool"] == name), None)
            if idx is None:
                continue
            c = pending.pop(idx)
            out.append({**c, "reason": reason})
            last_time = c.get("finished_at")
    out.extend({**c, "reason": None} for c in pending)      # calls not visible in the messages (should not happen)
    return out


def _excerpt(d: dict) -> str:
    if isinstance(d.get("summary"), str):
        return d["summary"][:EXCERPT_MAX]
    base = d.get("record") if isinstance(d.get("record"), dict) else d
    parts = [f"{k}={v}" for k, v in base.items()
             if k not in ("evidence_ref", "evidence_refs") and isinstance(v, (str, int, float, bool))]
    if isinstance(base.get("categories"), list):
        parts.append("categories=" + ",".join(map(str, base["categories"])))
    return "; ".join(parts)[:EXCERPT_MAX]


def evidence_index(evidence_results: list[dict]) -> dict[str, dict]:
    """ref -> {tool, event_type, time, account, host, ips, excerpt} for every evidence_ref in the FULL results of
    this phase's successful read calls (the first record that carries a ref wins)."""
    out: dict[str, dict] = {}

    def walk(v: Any, tool: str) -> None:
        if isinstance(v, dict):
            ref = v.get("evidence_ref")
            if isinstance(ref, str) and ref not in out:
                rec = v.get("record") if isinstance(v.get("record"), dict) else {}
                kind = v.get("kind")
                ips = [x for x in (v.get("src_ip"), v.get("dst_ip"), v.get("ip"), rec.get("ip")) if isinstance(x, str)]
                ips += [x for x in rec.get("usual_source_ips", []) if isinstance(x, str)]
                out[ref] = {"tool": tool, "event_type": v.get("event_type"), "time": v.get("time"),
                            "account": v.get("account") or (rec.get("name") if kind == "account" else None),
                            "host": v.get("host") or (rec.get("name") if kind == "host" else None),
                            "ips": list(dict.fromkeys(ips)), "excerpt": _excerpt(v)}
            for k, x in v.items():
                if k != "record":
                    walk(x, tool)
        elif isinstance(v, list):
            for x in v:
                walk(x, tool)

    for r in evidence_results:
        walk(r.get("result"), r.get("tool", "?"))
    return out


def save_phase(settings: Any, ctx: Any, phase: str, *, record: dict, allowed: set[str], messages: list | None,
               status: str, error: str | None, warnings: list[str], output: Any = None,
               mock_scenario: str | None = None, run_record: str | None = None) -> None:
    """Write one finished phase run (its task, tool calls in order with reasons, evidence) to the database."""
    from soc_agent.planner import HERMES_JSON_REPLIES

    store = Store(settings.db_path)
    store.ensure_investigation(ctx.investigation_id, ctx.alert, settings.llm_provider, settings.model,
                               settings.is_mock)
    task = record.get("task") or {}
    calls = audit_sequence(ctx.tool_calls, messages, allowed, HERMES_JSON_REPLIES)
    # Hermes stops a run after 3 consecutive turns without a valid tool call and does NOT append that last call to
    # the messages: record it from Hermes's error so the audit trail still shows it
    herr = str((record.get("hermes") or {}).get("error") or "")
    if herr.startswith("Model generated invalid tool call: "):
        t = calls[-1].get("finished_at") if calls else None
        calls.append({"tool": herr.split(": ", 1)[1][:80], "permission": None, "arguments": None,
                      "status": "refused_by_hermes", "result": {"hermes_error": herr},
                      "result_summary": "never executed: Hermes stopped the run (3 consecutive calls to tools "
                                        "outside the toolset)", "evidence_refs": [], "reason": None,
                      "started_at": t, "finished_at": t, "duration_ms": None})
    store.record_phase(
        ctx.investigation_id, phase, system_prompt=task.get("system_prompt"), user_message=task.get("user_message"),
        exposed_tools=record.get("exposed_tools") or [], started_at=record.get("started_at") or now(),
        finished_at=record.get("finished_at") or now(), status=status, hermes=record.get("hermes"), error=error,
        warnings=warnings, calls=calls, evidence_results=ctx.evidence_results, output=output, mock_scenario=mock_scenario, run_record=run_record)


def start_phase(settings: Any, investigation_id: str, alert: dict, phase: str) -> Store:
    """Create the investigation if needed and move it to Under Investigation as a phase starts. A closed
    investigation, or one that belongs to another alert, is refused."""
    store = Store(settings.db_path)
    if not store.ensure_investigation(investigation_id, alert, settings.llm_provider, settings.model,
                                      settings.is_mock):
        inv = store.investigation(investigation_id)
        if inv["status"] == CLOSED:
            raise StoreError(f"investigation {investigation_id} is closed; start a new run")
        if inv["alert_id"] != alert["alert_id"]:
            raise StoreError(f"investigation {investigation_id} is for alert {inv['alert_id']}, not {alert['alert_id']}")
    store.set_status(investigation_id, UNDER_INVESTIGATION, "system", f"{phase} phase started", if_from={OPEN})
    return store
