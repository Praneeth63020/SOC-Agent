"""Alert intake: load a JSON alert (normalized or Wazuh format), normalize, validate.

The agent only ever sees the normalized shape (schemas/alert.schema.json), so the
SIEM / detection layer can change without changing the agent.

    normalized JSON  ->  validated as-is (unknown keys are rejected)
    Wazuh alert JSON ->  mapped to the normalized shape, original kept under "raw"
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from soc_agent.schemas import SchemaError, validate

# Wazuh rule.level (0-15) -> the source's severity claim
_WAZUH_LEVEL = [(13, "critical"), (10, "high"), (6, "medium"), (0, "low")]


class AlertError(ValueError):
    pass


def wazuh_severity(level: int | None) -> str:
    if level is None:
        return "unknown"
    return next(s for lv, s in _WAZUH_LEVEL if level >= lv)


def _utc_iso(ts: str) -> str:
    """Wazuh '2026-11-18T09:42:17.512+0000' -> '2026-11-18T09:42:17.512000+00:00'."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(ts, fmt).astimezone(timezone.utc).isoformat()
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError as e:
        raise AlertError(f"Unreadable timestamp: {ts!r}") from e
    if dt.tzinfo is None:
        raise AlertError(f"Timestamp has no timezone: {ts!r}")
    return dt.astimezone(timezone.utc).isoformat()


def is_wazuh(raw: dict) -> bool:
    return isinstance(raw.get("rule"), dict) and isinstance(raw.get("agent"), dict) and "timestamp" in raw


def _obj(value) -> dict:
    """Wazuh fields that should be objects; anything else is treated as missing."""
    return value if isinstance(value, dict) else {}


def normalize_wazuh(raw: dict) -> dict:
    rule, agent, data = raw["rule"], raw["agent"], _obj(raw.get("data"))
    level = rule.get("level")
    level = int(level) if isinstance(level, (int, str)) and str(level).isdigit() else None
    decoder = _obj(raw.get("decoder")).get("name")
    groups = rule.get("groups")
    groups = " ".join(g for g in groups if isinstance(g, str)) if isinstance(groups, list) else ""
    category = "authentication" if ("authentication" in groups or decoder == "sshd") else "other"
    dstport = str(data.get("dstport", ""))
    mitre = _obj(rule.get("mitre")).get("id")
    entities = {
        "account": data.get("dstuser") or data.get("srcuser"),
        "host": agent.get("name"),
        "src_ip": data.get("srcip"),
        "dst_ip": agent.get("ip"),
        "dst_port": int(dstport) if dstport.isdigit() else None,
        "service": decoder,
    }
    observations = {}
    if "frequency" in rule:
        observations["rule_frequency"] = rule["frequency"]
    if raw.get("location"):
        observations["log_location"] = raw["location"]
    source = {
        "type": "wazuh",
        "rule_id": str(rule["id"]) if rule.get("id") is not None else None,
        "rule_description": rule.get("description"),
        "rule_level": level,
        "mitre_hint": [mitre] if isinstance(mitre, str) else mitre,   # kept as hints, not conclusions
    }
    return {
        "alert_id": f"WAZUH-{raw.get('id', 'unknown')}".replace(" ", ""),
        "timestamp": _utc_iso(str(raw["timestamp"])),
        "source": {k: v for k, v in source.items() if v not in (None, "", [])},
        "category": category,
        "title": rule.get("description") or "Wazuh alert",
        "description": str(raw.get("full_log", ""))[:2000],
        "severity_hint": wazuh_severity(level),
        "entities": {k: v for k, v in entities.items() if v not in (None, "")},
        "observations": observations,
        # Wazuh has no "synthetic" field: lab files carry a _comment marker instead
        "synthetic": "SYNTHETIC" in str(raw.get("_comment", "")).upper(),
        "raw": raw,
    }


def normalize(raw: dict) -> dict:
    """Return a schema-valid normalized alert or raise AlertError with readable problems."""
    if not isinstance(raw, dict):
        raise AlertError("Alert must be a JSON object")
    try:
        alert = normalize_wazuh(raw) if is_wazuh(raw) else raw
    except (TypeError, AttributeError, ValueError) as e:   # unexpected field types in a raw alert
        if isinstance(e, AlertError):
            raise
        raise AlertError(f"Wazuh alert has an unexpected shape: {type(e).__name__}: {e}") from e
    try:
        validate(alert, "alert", "Alert")
    except SchemaError as e:
        raise AlertError(str(e)) from e
    try:   # the schema pattern checks the shape; this checks it is a real date
        datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))
    except ValueError as e:
        raise AlertError(f"Alert is invalid: timestamp: {alert['timestamp']!r} is not a real date") from e
    return alert


def load_alert(path: str | Path) -> dict:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise AlertError(f"Alert file not found: {path}") from e
    except IsADirectoryError as e:
        raise AlertError(f"{path} is a directory, not an alert file") from e
    except OSError as e:
        raise AlertError(f"Cannot read {path}: {e.strerror or e}") from e
    except UnicodeDecodeError as e:
        raise AlertError(f"{path.name} is not UTF-8 text") from e
    except json.JSONDecodeError as e:
        raise AlertError(f"{path.name} is not valid JSON: {e}") from e
    return normalize(raw)
