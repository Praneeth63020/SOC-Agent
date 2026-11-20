"""Alert intake: normalization (Wazuh), schema validation, rejection of bad input."""
import copy
from pathlib import Path

import pytest

from soc_agent.alerts import AlertError, load_alert, normalize, wazuh_severity

ALERTS = Path(__file__).resolve().parent.parent / "data" / "alerts"


def test_sample_alert_is_valid(alert):
    assert alert["alert_id"] == "ALERT-2026-0001" and alert["synthetic"] is True
    assert alert["entities"] == {"account": "j.mehta", "host": "fin-app-01", "src_ip": "203.0.113.77",
                                 "dst_ip": "10.20.5.17", "dst_port": 22, "service": "sshd"}
    assert alert["observations"]["failed_attempts"] == 50


def test_wazuh_alert_is_normalized(wazuh_raw):
    a = normalize(wazuh_raw)
    assert a["source"] == {"type": "wazuh", "rule_id": "40112", "rule_level": 12,
                           "rule_description": "Multiple authentication failures followed by a success.",
                           "mitre_hint": ["T1110", "T1078"]}
    assert a["category"] == "authentication" and a["severity_hint"] == "high"
    assert a["entities"] == {"account": "j.mehta", "host": "fin-app-01", "src_ip": "203.0.113.77",
                             "dst_ip": "10.20.5.17", "dst_port": 22, "service": "sshd"}
    assert a["timestamp"] == "2026-11-18T09:42:17.512000+00:00"
    assert a["synthetic"] is True and a["raw"] == wazuh_raw          # original kept for traceability


def test_wazuh_and_normalized_samples_describe_the_same_event(alert, wazuh_raw):
    w = normalize(wazuh_raw)
    assert w["entities"] == alert["entities"] and w["timestamp"] == alert["timestamp"]
    assert w["source"] == alert["source"] and w["severity_hint"] == alert["severity_hint"]


@pytest.mark.parametrize("level, expected", [(0, "low"), (5, "low"), (6, "medium"), (9, "medium"),
                                             (10, "high"), (12, "high"), (13, "critical"), (15, "critical"),
                                             (None, "unknown")])
def test_wazuh_level_to_severity_hint(level, expected):
    assert wazuh_severity(level) == expected


def test_wazuh_level_mapping_through_normalize(wazuh_raw):
    wazuh_raw["rule"]["level"] = 14
    assert normalize(wazuh_raw)["severity_hint"] == "critical"
    del wazuh_raw["rule"]["level"]
    assert normalize(wazuh_raw)["severity_hint"] == "unknown"


def test_wazuh_without_synthetic_marker_is_not_labelled_synthetic(wazuh_raw):
    wazuh_raw.pop("_comment")
    assert normalize(wazuh_raw)["synthetic"] is False


def test_wazuh_invalid_source_ip_is_rejected(wazuh_raw):
    wazuh_raw["data"]["srcip"] = "203.0.113.300"
    with pytest.raises(AlertError, match="ipv4"):
        normalize(wazuh_raw)


def _clean(alert):
    return copy.deepcopy({k: v for k, v in alert.items() if k != "raw"})


@pytest.mark.parametrize("mutate, message", [
    (lambda a: a.pop("entities"), "entities"),
    (lambda a: a.pop("synthetic"), "synthetic"),
    (lambda a: a.pop("alert_id"), "alert_id"),
    (lambda a: a["entities"].update(src_ip="999.1.1.1"), "ipv4"),
    (lambda a: a["entities"].update(dst_port=70000), "65535"),
    (lambda a: a.update(category="weird"), "category"),
    (lambda a: a.update(severity_hint="urgent"), "severity_hint"),
    (lambda a: a.update(unexpected=True), "unexpected"),
    (lambda a: a.update(_comment="hello"), "_comment"),
    (lambda a: a["entities"].update(mac="aa:bb"), "mac"),
    (lambda a: a["source"].update(type="splunk"), "splunk"),
    (lambda a: a.update(alert_id="x"), "alert_id"),
    (lambda a: a.update(timestamp="2026-11-18T15:12:17+05:30"), "timestamp"),
    (lambda a: a.update(timestamp="2026-13-40T09:42:17Z"), "timestamp"),
    (lambda a: a.update(observations={"nested": {"a": 1}}), "nested"),
])
def test_invalid_alerts_are_rejected(alert, mutate, message):
    a = _clean(alert)
    mutate(a)
    with pytest.raises(AlertError, match=message):
        normalize(a)


def test_invalid_demo_alert_file_lists_every_problem():
    with pytest.raises(AlertError) as e:
        load_alert(ALERTS / "invalid" / "bad_alert.json")
    msg = str(e.value)
    assert "203.0.113.777" in msg and "priority" in msg and "timestamp" in msg


def test_bad_files(tmp_path):
    with pytest.raises(AlertError, match="not found"):
        load_alert(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(AlertError, match="not valid JSON"):
        load_alert(bad)
    binary = tmp_path / "bin.json"
    binary.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(AlertError):
        load_alert(binary)
    with pytest.raises(AlertError, match="JSON object"):
        normalize([1, 2])
