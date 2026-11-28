"""Evidence tools (Day 2): search_logs, lookup_ip, search_cve, get_asset_context. All read-only.

Each tool reads a local file under data/ (SYNTHETIC logs and assets, MOCK intelligence).
No tool makes a network call or touches a real system. Input and output schemas live in
schemas/tools/<tool>.input.json / .output.json; the wrapper (tools/base.py) validates
both, so a tool either returns a result of the documented shape or an error.

Every record a tool returns carries an evidence_ref that points at exactly one place in
the data files (see resolve_ref). Zero results are a normal result, never an error.
A missing or corrupt data file is a ToolFailure (status "error"), never a crash.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from soc_agent.schemas import load_tool_schema
from soc_agent.tools.base import DEFAULT_DATA_DIR, RunContext, ToolFailure, ToolRejection, ToolSpec

WAZUH_FILE = "logs/wazuh_alerts.jsonl"
TSHARK_FILE = "logs/tshark_sessions.csv"
IP_FILE = "intel/ip_reputation.json"
CVE_FILE = "intel/cve_db.json"
INVENTORY_FILE = "assets/inventory.json"
MAX_WINDOW = timedelta(days=30)
SUMMARY_MAX = 240
TSHARK_COLUMNS = ("frame.time_epoch", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "tcp.stream",
                  "duration_s", "bytes")
TSHARK_NOTE = ("tshark rows are TCP sessions only: SSH is encrypted, so they show volume, timing, duration and "
               "bytes, never whether a login succeeded (that comes from Wazuh).")
# lookup_ip treats only these as internal. NOTE: Python's is_private is NOT used, because it also
# covers the RFC 5737 documentation ranges that this lab uses as stand-ins for internet addresses.
INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in
                      ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"))


# ------------------------------------------------------------------ data access
def data_dir_synthetic(data_dir: Path | str) -> bool:
    """True if the data root is marked as lab data: every JSON data file present carries "_synthetic": true and
    the Wazuh export (if present) starts with the SYNTHETIC header line. Independent of the alert's own marker."""
    root, seen = Path(data_dir), 0
    for rel in (INVENTORY_FILE, IP_FILE, CVE_FILE):
        try:
            data = json.loads((root / rel).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not (isinstance(data, dict) and data.get("_synthetic") is True):
            return False
        seen += 1
    try:
        with (root / WAZUH_FILE).open("rb") as fh:
            if b'"_synthetic": true' not in fh.readline():
                return False
    except OSError:
        pass
    return seen > 0


def _read_text(ctx: RunContext, rel: str) -> str:
    path = Path(ctx.data_dir) / rel
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ToolFailure(f"Data source {path.name} is unavailable (file not found).") from None
    except UnicodeDecodeError:
        raise ToolFailure(f"Data source {path.name} is corrupt (not UTF-8 text).") from None
    except OSError as e:
        raise ToolFailure(f"Data source {path.name} cannot be read ({e.strerror or type(e).__name__}).") from None


def _read_json(ctx: RunContext, rel: str) -> dict:
    name = Path(rel).name
    try:
        data = json.loads(_read_text(ctx, rel))
    except json.JSONDecodeError as e:
        raise ToolFailure(f"Data source {name} is corrupt (not valid JSON: {e.msg} at line {e.lineno}).") from None
    if not isinstance(data, dict):
        raise ToolFailure(f"Data source {name} is corrupt (expected a JSON object).")
    return data


def _section(data: dict, key: str, name: str) -> dict:
    v = data.get(key)
    if not isinstance(v, dict):
        raise ToolFailure(f"Data source {name} is corrupt (missing '{key}' object).")
    return v


def _public(record: dict) -> dict:
    """A data record without internal annotations such as _note / _comment."""
    return {k: v for k, v in record.items() if not str(k).startswith("_")}


# ------------------------------------------------------------------------ times
def parse_utc(text: str) -> datetime:
    """'2026-11-18T09:30:00Z' / '+00:00' (also Wazuh's '+0000') -> aware UTC datetime. ValueError if not."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(text, fmt).astimezone(timezone.utc)
        except ValueError:
            continue
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"{text!r} has no time zone")
    return dt.astimezone(timezone.utc)


def fmt_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# ------------------------------------------------------------------- log parsing
_GROUP_TYPES = (({"authentication_failed", "authentication_failures", "invalid_login"}, "auth_failure"),
                ({"authentication_success"}, "auth_success"),
                ({"sudo", "su"}, "privilege"),
                ({"adduser", "addgroup", "userdel", "account_changed", "passwd"}, "account_change"))


def _ip_or_none(value: Any) -> str | None:
    try:
        return str(ipaddress.IPv4Address(str(value))) if value not in (None, "") else None
    except ValueError:
        return None


def _wazuh_event(raw: dict, ref: str) -> dict | None:
    """One Wazuh alert -> normalized event, or None if the line is unusable."""
    try:
        when = parse_utc(str(raw["timestamp"]))
        rule, agent = raw["rule"], raw["agent"]
        data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        groups = {g for g in rule.get("groups") or [] if isinstance(g, str)}
        etype = next((t for gs, t in _GROUP_TYPES if groups & gs), "other")
        account = data.get("srcuser") if etype == "privilege" else (data.get("dstuser") or data.get("srcuser"))
        port = str(data.get("dstport", ""))
        summary = f"Wazuh rule {rule.get('id')} (level {rule.get('level')}) {rule.get('description', '')} | " \
                  f"{raw.get('full_log', '')}"
        return {"time": fmt_utc(when), "source": "wazuh", "event_type": etype,
                "account": str(account) if account else None, "host": agent.get("name"),
                "src_ip": _ip_or_none(data.get("srcip")), "dst_ip": _ip_or_none(agent.get("ip")),
                "dst_port": int(port) if port.isdigit() else None,
                "summary": summary[:SUMMARY_MAX], "evidence_ref": ref}
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def wazuh_events(ctx: RunContext) -> tuple[list[dict], int]:
    """(events, malformed lines skipped). evidence_ref = physical line number (header included)."""
    events, malformed = [], 0
    for n, line in enumerate(_read_text(ctx, WAZUH_FILE).splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if isinstance(raw, dict) and "_comment" in raw and "rule" not in raw:
            continue                                   # the SYNTHETIC header line
        ev = _wazuh_event(raw, f"wazuh_alerts.jsonl#L{n}") if isinstance(raw, dict) else None
        if ev is None:
            malformed += 1
        else:
            events.append(ev)
    return events, malformed


def _tshark_rows(text: str, name: str) -> list[dict]:
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    reader = csv.DictReader(lines)
    if not reader.fieldnames or not set(TSHARK_COLUMNS) <= set(reader.fieldnames):
        raise ToolFailure(f"Data source {name} is corrupt (expected the columns {', '.join(TSHARK_COLUMNS)}).")
    return list(reader)


def host_map(ctx: RunContext) -> dict[str, str]:
    """IP -> host name from the asset inventory (used to name tshark endpoints)."""
    hosts = _section(_read_json(ctx, INVENTORY_FILE), "hosts", "inventory.json")
    return {str(h.get("ip")): name for name, h in hosts.items() if isinstance(h, dict) and h.get("ip")}


def tshark_events(ctx: RunContext) -> tuple[list[dict], int]:
    """(events, malformed rows skipped). evidence_ref = data row number below the header."""
    rows = _tshark_rows(_read_text(ctx, TSHARK_FILE), "tshark_sessions.csv")
    names = host_map(ctx)
    events, malformed = [], 0
    for n, row in enumerate(rows, 1):
        try:
            when = datetime.fromtimestamp(float(row["frame.time_epoch"]), tz=timezone.utc)
            src, dst = str(ipaddress.IPv4Address(row["ip.src"])), str(ipaddress.IPv4Address(row["ip.dst"]))
            sport, dport, stream = int(row["tcp.srcport"]), int(row["tcp.dstport"]), int(row["tcp.stream"])
            duration, size = float(row["duration_s"]), int(row["bytes"])
        except (KeyError, TypeError, ValueError):
            malformed += 1
            continue
        events.append({
            "time": fmt_utc(when), "source": "tshark", "event_type": "network_session", "account": None,
            "host": names.get(dst) or names.get(src), "src_ip": src, "dst_ip": dst, "dst_port": dport,
            "summary": f"TCP session {src}:{sport} -> {dst}:{dport} (tcp.stream {stream}), "
                       f"duration {duration:g} s, {size} bytes",
            "evidence_ref": f"tshark_sessions.csv#row{n}"})
    return events, malformed


# -------------------------------------------------------------------- search_logs
def _window(args: dict) -> tuple[datetime | None, datetime | None]:
    issues, bounds = [], {}
    for key in ("start", "end"):
        if key in args:
            try:
                bounds[key] = parse_utc(args[key])
            except ValueError:
                issues.append(f"{key}: {args[key]!r} is not a real date and time")
    if issues:
        raise ToolRejection("Invalid time window.", issues)
    start, end = bounds.get("start"), bounds.get("end")
    if end and "." not in args["end"]:        # "...T09:42:17Z" covers the whole second (09:42:17.512 matches)
        end = end.replace(microsecond=999999)
    if start and end and start > end:
        raise ToolRejection("Invalid time window.", [f"start ({args['start']}) is after end ({args['end']})"])
    if start and end and end - start > MAX_WINDOW:
        raise ToolRejection("Invalid time window.", [f"the window is {(end - start).days} days; the maximum is "
                                                     f"{MAX_WINDOW.days} days"])
    return start, end


def _matches(ev: dict, args: dict, start: datetime | None, end: datetime | None, host_ips: set[str]) -> bool:
    if args.get("account") and (ev["account"] or "").lower() != args["account"].lower():
        return False
    if args.get("host"):      # the named host, or either endpoint of a session (name resolved via inventory)
        h = args["host"].lower()
        if (ev["host"] or "").lower() != h and not ({h} | host_ips) & {ev["src_ip"], ev["dst_ip"]}:
            return False
    for key in ("src_ip", "dst_ip", "dst_port"):
        if key in args and ev[key] != args[key]:
            return False
    if args.get("event_type", "any") != "any" and ev["event_type"] != args["event_type"]:
        return False
    if start or end:
        t = parse_utc(ev["time"])
        if (start and t < start) or (end and t > end):
            return False
    return True


def _search_logs(args: dict, ctx: RunContext) -> dict:
    start, end = _window(args)
    query = {"event_type": "any", "limit": 50, **args}
    events, malformed, host_ips = [], 0, set()
    if args.get("host") and args["source"] in ("tshark", "all"):
        host_ips = {ip for ip, name in host_map(ctx).items() if name.lower() == args["host"].lower()}
    if args["source"] in ("wazuh", "all"):
        evs, bad = wazuh_events(ctx)
        events += evs
        malformed += bad
    if args["source"] in ("tshark", "all"):
        evs, bad = tshark_events(ctx)
        events += evs
        malformed += bad
    matched = sorted((e for e in events if _matches(e, args, start, end, host_ips)),
                     key=lambda e: (e["time"], e["source"], e["evidence_ref"]))
    limit = query["limit"]
    shown = matched[:limit]
    notes = []
    if not matched:
        notes.append("No events matched. This is a valid result (absence of matching events), not an error.")
    if len(matched) > limit:
        fix = ("call again with limit=200" if len(matched) <= 200 and limit < 200 else
               "narrow the time window or the filters")
        notes.append(f"Only the earliest {limit} of {len(matched)} matching events are returned: the LATEST "
                     f"{len(matched) - limit} are missing (a successful login or what followed it may be among them); "
                     f"{fix} to see them. counts cover all matches.")
    if any(e["source"] == "tshark" for e in matched):
        notes.append(TSHARK_NOTE)
    return {
        "query": query, "events": shown, "total_matched": len(matched), "returned": len(shown),
        "truncated": len(matched) > limit, "malformed_lines_skipped": malformed,
        "counts": {"by_event_type": dict(Counter(e["event_type"] for e in matched)),
                   "by_source": dict(Counter(e["source"] for e in matched))},
        "first_time": matched[0]["time"] if matched else None,
        "last_time": matched[-1]["time"] if matched else None,
        "notes": notes, "data_label": "SYNTHETIC",
    }


def _summarize_search(r: dict) -> str:
    kinds = ", ".join(f"{k} {v}" for k, v in sorted(r["counts"]["by_event_type"].items()))
    return (f"{r['total_matched']} matched, {r['returned']} returned{' (truncated)' if r['truncated'] else ''}"
            f"{'; ' + kinds if kinds else ''}; {r['malformed_lines_skipped']} malformed line(s) skipped")


SEARCH_LOGS = ToolSpec(
    name="search_logs",
    description=("Search the SYNTHETIC lab logs: Wazuh alerts (login failures/successes, sudo, new accounts) and "
                 "tshark TCP sessions (connections, timing, duration, bytes; SSH is encrypted, so no login outcome). "
                 "Give source plus at least one filter (account, host, src_ip, dst_ip, dst_port, event_type, start, "
                 "end). Times are ISO 8601 UTC like 2026-11-18T09:30:00Z; window at most 30 days. Returns "
                 "normalized events sorted by time, each with an evidence_ref, plus counts over all matches. "
                 "Zero matches is a valid result."),
    parameters=load_tool_schema("search_logs", "input"),
    handler=_search_logs,
    permission="read",
    output_schema=load_tool_schema("search_logs", "output"),
    summarize=_summarize_search,
)


# ---------------------------------------------------------------------- lookup_ip
_IP_FIELDS = ("classification", "reputation_score", "categories", "report_count", "first_seen", "last_seen",
              "asn", "as_org", "country")
_INTEL = {"source": "MOCK intel feed", "live": False, "data_label": "MOCK"}


def _lookup_ip(args: dict, ctx: RunContext) -> dict:
    ip = ipaddress.IPv4Address(args["ip"])
    if ip.is_multicast or ip.is_unspecified or ip == ipaddress.IPv4Address("255.255.255.255"):
        raise ToolRejection(f"{ip} is not a unicast host address.")
    if any(ip in net for net in INTERNAL_NETS):
        return {"ip": str(ip), "found": False, "classification": "internal", **_INTEL,
                "note": "Internal address (RFC 1918, loopback or link-local): not looked up in the intel feed. "
                        "Use get_asset_context or search_logs for internal context."}
    records = _section(_read_json(ctx, IP_FILE), "records", "ip_reputation.json")
    rec = records.get(str(ip))
    if not isinstance(rec, dict):
        return {"ip": str(ip), "found": False, "classification": "unknown", **_INTEL,
                "note": "No record in the MOCK intel feed. Absence of data does not mean the address is benign."}
    out = {"ip": str(ip), "found": True, **{k: rec[k] for k in _IP_FIELDS if k in rec}, **_INTEL,
           "evidence_ref": f"ip_reputation.json#{ip}"}
    out.setdefault("classification", "unknown")
    return out


def _summarize_ip(r: dict) -> str:
    if r["found"]:
        return (f"{r['ip']}: {r['classification']} (score {r.get('reputation_score')}; "
                f"{', '.join(r.get('categories', []))}; {r.get('report_count', 0)} reports) [MOCK]")
    return f"{r['ip']}: {r['classification']}, no intel record [MOCK feed]"


LOOKUP_IP = ToolSpec(
    name="lookup_ip",
    description=("Look up an IPv4 address in the approved intelligence feed (a local MOCK feed: no live service is "
                 "queried). Internal (RFC 1918) addresses are classified 'internal' without a lookup. Unknown "
                 "addresses return found=false, which does not mean benign."),
    parameters=load_tool_schema("lookup_ip", "input"),
    handler=_lookup_ip,
    permission="read",
    output_schema=load_tool_schema("lookup_ip", "output"),
    summarize=_summarize_ip,
)


# --------------------------------------------------------------------- search_cve
_VERSION = re.compile(r"^(?:\d+:)?(?P<v>(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<micro>\d+))?(?:p(?P<patch>\d+))?)"
                      r"(?:[-+~].*)?$")


def parse_version(text: str) -> tuple[str, tuple[int, int, int, int]]:
    """'8.9p1' -> ('8.9p1', (8, 9, 0, 1)); '1:8.9p1-3ubuntu0.6' -> ('8.9p1', ...); '0' -> ('0', (0, 0, 0, 0))."""
    if text.strip() == "0":
        return "0", (0, 0, 0, 0)
    m = _VERSION.match(text.strip())
    if not m:
        raise ValueError(text)
    return m["v"], (int(m["major"]), int(m["minor"]), int(m["micro"] or 0), int(m["patch"] or 0))


def _affected(version: tuple, ranges: list[dict]) -> bool:
    """introduced <= version < fixed, for any of the ranges."""
    return any(parse_version(r["introduced"])[1] <= version < parse_version(r["fixed"])[1] for r in ranges)


def _search_cve(args: dict, ctx: RunContext) -> dict:
    compared = key = None
    if "version" in args:
        try:
            compared, ver = parse_version(args["version"])
        except ValueError:
            raise ToolRejection(f"version {args['version']!r} is not a version like 8.9p1, 9.6 or 1:8.9p1-3ubuntu0.6.",
                                hint="Call search_cve again without version to list every CVE for the product.")
    db = _read_json(ctx, CVE_FILE)
    products = _section(db, "products", "cve_db.json")
    wanted = args["product"].lower()
    key = next((p for p, meta in products.items()
                if wanted == p.lower() or wanted in [a.lower() for a in (meta or {}).get("aliases", [])]), None)
    cves = db.get("cves")
    if not isinstance(cves, list):
        raise ToolFailure("Data source cve_db.json is corrupt (missing 'cves' list).")
    matches = []
    for c in cves:
        if not isinstance(c, dict) or c.get("product") != key:
            continue
        try:
            hit = compared is None or _affected(ver, c["affected"])
        except (KeyError, TypeError, ValueError):
            raise ToolFailure(f"Data source cve_db.json is corrupt (bad version range in {c.get('cve_id')}).") from None
        if hit:
            matches.append({k: c[k] for k in ("cve_id", "cvss", "severity", "summary", "affected")}
                           | {"evidence_ref": f"cve_db.json#{c['cve_id']}"})
    notes = []
    if key is None:
        notes.append(f"Product {args['product']!r} is not in the MOCK CVE database; no CVEs can be listed.")
    elif compared is None:
        notes.append("No version given: every CVE recorded for the product is listed; which ones apply is unknown.")
    elif not matches:
        notes.append(f"No CVE in the MOCK database affects {key} {compared}. This is a valid result.")
    if key is not None:
        notes.append("Upstream version ranges only: distribution backports (e.g. Ubuntu security updates) are not "
                     "considered, so a listed CVE may already be fixed in the installed package.")
    return {"product": args["product"], "product_matched": key, "version": args.get("version"),
            "version_compared": compared, "version_checked": compared is not None, "matches": matches,
            "total": len(matches), "notes": notes, "source": "MOCK CVE database", "live": False, "data_label": "MOCK"}


def _summarize_cve(r: dict) -> str:
    ids = ", ".join(m["cve_id"] for m in r["matches"]) or "none"
    return f"{r['product']} {r['version_compared'] or '(any version)'}: {r['total']} CVE(s): {ids} [MOCK]"


SEARCH_CVE = ToolSpec(
    name="search_cve",
    description=("Find known vulnerabilities for a product (e.g. openssh; sshd is accepted) and optionally a version "
                 "(e.g. 8.9p1) in the approved vulnerability data (a local MOCK CVE database: no live service). "
                 "Version-range aware; an empty list is a valid result."),
    parameters=load_tool_schema("search_cve", "input"),
    handler=_search_cve,
    permission="read",
    output_schema=load_tool_schema("search_cve", "output"),
    summarize=_summarize_cve,
)


# --------------------------------------------------------------- get_asset_context
def _get_asset_context(args: dict, ctx: RunContext) -> dict:
    inv = _read_json(ctx, INVENTORY_FILE)
    kind = "host" if "host" in args else "account"
    query = args[kind]
    section = _section(inv, kind + "s", "inventory.json")
    q = query.lower()
    name = next((n for n, rec in section.items() if n.lower() == q
                 or (kind == "host" and isinstance(rec, dict) and rec.get("ip") == query)), None)
    if name is None or not isinstance(section[name], dict):
        return {"kind": kind, "query": query, "found": False, "data_label": "SYNTHETIC",
                "note": f"No {kind} record in the asset inventory. Unknown assets need manual follow-up."}
    return {"kind": kind, "query": query, "found": True, "record": {"name": name, **_public(section[name])},
            "evidence_ref": f"inventory.json#{kind}s/{name}", "data_label": "SYNTHETIC"}


def _summarize_asset(r: dict) -> str:
    if not r["found"]:
        return f"{r['kind']} {r['query']}: not in the inventory"
    rec = r["record"]
    if r["kind"] == "host":
        svc = ", ".join(f"{s['product']} {s['version']}" for s in rec.get("services", []))
        return (f"host {rec['name']}: {rec['role']}; criticality {rec['criticality']}; internet_exposed "
                f"{rec['internet_exposed']}; {svc}")
    return (f"account {rec['name']}: {rec['role']}; privileged {rec['privileged']}; usual IPs "
            f"{', '.join(rec['usual_source_ips'])}")


GET_ASSET_CONTEXT = ToolSpec(
    name="get_asset_context",
    description=("Business context from the SYNTHETIC asset inventory: for a host (name or IP) its role, criticality, "
                 "owner, OS, services with versions and internet exposure; for an account its role, privileged flag "
                 "and usual locations / source IPs. Give exactly one of host or account."),
    parameters=load_tool_schema("get_asset_context", "input"),
    handler=_get_asset_context,
    permission="read",
    output_schema=load_tool_schema("get_asset_context", "output"),
    summarize=_summarize_asset,
)

EVIDENCE_TOOLS = [SEARCH_LOGS, LOOKUP_IP, SEARCH_CVE, GET_ASSET_CONTEXT]


# ------------------------------------------------------------------ evidence refs
_REF = re.compile(r"^(?P<file>[a-z_]+\.(?:jsonl|csv|json))#(?P<key>.+)$")


def resolve_ref(ref: str, data_dir: Path | str | None = None) -> Any:
    """The raw record an evidence_ref points at (a log line, a CSV row, a JSON record), or None.
    Lets a reviewer (and Day 3's checks) verify that a cited ref says what a claim says."""
    m = _REF.match(ref)
    if not m:
        return None
    ctx = RunContext("resolve", {}, data_dir=Path(data_dir) if data_dir else DEFAULT_DATA_DIR)
    f, key = m["file"], m["key"]
    try:
        if f == "wazuh_alerts.jsonl" and (n := re.fullmatch(r"L([1-9]\d*)", key)):
            lines = _read_text(ctx, WAZUH_FILE).splitlines()
            return lines[int(n[1]) - 1] if int(n[1]) <= len(lines) else None
        if f == "tshark_sessions.csv" and (n := re.fullmatch(r"row([1-9]\d*)", key)):
            rows = _tshark_rows(_read_text(ctx, TSHARK_FILE), f)
            return rows[int(n[1]) - 1] if int(n[1]) <= len(rows) else None
        if f == "ip_reputation.json":
            return _section(_read_json(ctx, IP_FILE), "records", f).get(key)
        if f == "cve_db.json":
            return next((c for c in _read_json(ctx, CVE_FILE).get("cves", []) if c.get("cve_id") == key), None)
        if f == "inventory.json" and "/" in key:
            section, name = key.split("/", 1)
            return _read_json(ctx, INVENTORY_FILE).get(section, {}).get(name)
    except ToolFailure:
        return None
    return None
