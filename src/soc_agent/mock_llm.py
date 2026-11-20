"""MOCK LLM: an in-process OpenAI-compatible server for offline demos, tests and CI.

!!! This is NOT an AI model. It is a deterministic script that imitates a
tool-calling LLM so the real Hermes pipeline (agent loop, tool dispatch, schema
validation, audit) can run without an NVIDIA API key. Everything it writes is
labelled [MOCK], and plans carry generated_by.mock = true. Use
SOC_LLM_PROVIDER=nvidia for real model reasoning.

It listens on 127.0.0.1 (random port) and serves GET /v1/models and
POST /v1/chat/completions (JSON or SSE stream - Hermes uses stream=True).

Scenarios:
  normal         get_alert -> submit a valid plan -> one short sentence
  invalid_first  first plan uses an IP that is not in the alert (rejected), then a valid plan
  escape         first tries Hermes's built-in `terminal` tool (must be refused by Hermes)
  bad_args       first calls get_alert with malformed arguments (rejected by the wrapper)
  string_plan    first sends the plan as a malformed JSON string (seen with a live NVIDIA model), then fixes it
  no_submit      answers in plain text and never submits a plan
  http_error     every chat request fails with HTTP 500
"""
from __future__ import annotations

import json
import re
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from soc_agent.config import MOCK_MODEL

SCENARIOS = ("normal", "invalid_first", "escape", "bad_args", "string_plan", "no_submit", "http_error")
# the escape scenario asks Hermes to run `touch ESCAPE_MARKER`; tests assert it never appears
ESCAPE_MARKER = Path(tempfile.gettempdir()) / "soc_agent_escape_marker"
INVENTED_IP = "198.51.100.23"       # documentation range, deliberately NOT in the sample alert
FINAL_REPLY = "[MOCK] Investigation plan submitted (scripted mock, not an AI model)."


def _m(text: str) -> str:
    return f"[MOCK] {text}"


def build_mock_plan(alert: dict) -> dict:
    """A fixed-template plan filled with values from the alert. Template, not reasoning."""
    e, obs = alert.get("entities", {}), alert.get("observations", {})
    acct, host, ip = e.get("account", "unknown"), e.get("host", "unknown"), e.get("src_ip")
    fails = obs.get("failed_attempts", obs.get("rule_frequency", "multiple"))
    window = {k: v for k, v in {"start": obs.get("failure_window_start"),
                                "end": obs.get("success_time", alert.get("timestamp"))}.items() if v}
    ip_txt = ip or "the source IP"
    steps = [
        ("Confirm the account, the asset and the authentication timeline.", "search_logs",
         {"account": acct, "host": host, "event_type": "authentication", **window},
         "Checks the failure count, timing and the successful login the alert reports (questions a, b).",
         "Timestamped failed and accepted sshd events for the account on the host."),
        (f"Find all other activity from {ip_txt} before and after the login.", "search_logs",
         {"src_ip": ip} if ip else {"host": host},
         "Shows whether the source also targeted other accounts or hosts (question d).",
         "Logins or connections from the source to other assets, if any (Wazuh + tshark sessions)."),
        (f"Check approved intelligence for {ip_txt}.", "lookup_ip", {"ip": ip} if ip else {"host": host},
         "Separates a known-bad source from a corporate, VPN or partner address (question c).",
         "Reputation, owner/ASN and prior sightings from the approved intelligence source."),
        (f"Get business context for {host}.", "get_asset_context", {"host": host},
         "Asset criticality and exposed services drive the justified severity (question e).",
         "Owner, criticality, operating system, exposed services and versions."),
        (f"Check what {acct} did on {host} after the successful login.", "search_logs",
         {"account": acct, "host": host, "event_type": "post_login"},
         "sudo use, new accounts or unusual outbound connections would support compromise (questions d, e).",
         "Session, sudo and process events after the login time, or their absence."),
        (f"Check known vulnerabilities for {e.get('service', 'the exposed service')} on {host}.", "search_cve",
         {"product": e.get("service", "unknown")},
         "An exploitable service would raise impact and change the recommendations (question e).",
         "CVE ids and severities for the installed version, if any."),
        ("Decide on containment with a human analyst.", "analyst_review",
         {"account": acct, "host": host, **({"src_ip": ip} if ip else {})},
         "Disabling the account, blocking the IP or isolating the host needs human approval (question f).",
         "An approved or rejected containment decision recorded by the analyst."),
    ]
    return {
        "summary": _m(f"Alert {alert['alert_id']} reports {fails} failed logins for {acct} on {host} followed by "
                      f"a successful login from {ip_txt}. This could be a successful password-guessing attack "
                      "or a benign user error; evidence is needed before any conclusion."),
        "hypotheses": [
            {"id": "H1", "benign": False,
             "description": _m(f"An attacker at {ip_txt} brute-forced or guessed the password of {acct}."),
             "would_be_supported_by": f"{ip_txt} has no prior history for {acct}, bad reputation, "
                                      "suspicious activity after the login.",
             "would_be_refuted_by": f"{ip_txt} is a known corporate or VPN address used by {acct} before."},
            {"id": "H2", "benign": False,
             "description": _m(f"Credential stuffing or password spraying, of which {acct} was one target."),
             "would_be_supported_by": "The same source also tried other accounts or hosts.",
             "would_be_refuted_by": f"All failures from the source target {acct} only."},
            {"id": "H3", "benign": True,
             "description": _m(f"The real user {acct}, or a script with a stale password, failed and then "
                               "logged in normally."),
             "would_be_supported_by": f"{ip_txt} matches the user's usual location or VPN; normal activity "
                                      "after login; the user confirms.",
             "would_be_refuted_by": "Unfamiliar source with bad reputation, or privilege escalation after login."},
        ],
        "key_questions": [
            f"Which account ({acct}) and asset ({host}) are involved, and how critical is {host}?",
            "What is the exact timeline of the failures and the successful login, and which events support it?",
            f"What does approved intelligence say about {ip_txt}?",
            f"What did {ip_txt} and {acct} do before and after the successful login?",
            "What severity is justified by the evidence, and what is still unknown?",
            "What containment should a human analyst consider?",
        ],
        "steps": [{"step": i, "objective": _m(o), "tool": t, "parameters": p, "rationale": r,
                   "expected_evidence": x} for i, (o, t, p, r, x) in enumerate(steps, 1)],
        "safety_notes": [
            f"Disabling {acct}, blocking {ip_txt} or isolating {host} requires explicit analyst approval.",
            "Only synthetic lab data is used; no live system is queried or changed.",
            "The alert's severity and MITRE hints are hints, not conclusions.",
        ],
        "data_gaps": [
            "The alert does not show what happened after the login.",
            f"Reputation and ownership of {ip_txt} are unknown until looked up.",
            f"The business criticality of {host} is not in the alert.",
        ],
    }


# ------------------------------------------------------------------ script
def _history(messages: list[dict]) -> list[tuple[str, str, str]]:
    """[(tool name, arguments json, result text)] for every tool call made so far, in order."""
    results = {m.get("tool_call_id"): m.get("content") or "" for m in messages if m.get("role") == "tool"}
    calls = []
    for m in messages:
        for tc in (m.get("tool_calls") or []) if m.get("role") == "assistant" else []:
            fn = tc.get("function") or {}
            calls.append((fn.get("name", ""), fn.get("arguments") or "", results.get(tc.get("id"), "")))
    return calls


def _json(text: str) -> dict:
    try:
        v = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return v if isinstance(v, dict) else {}


def _text(content: str) -> tuple[dict, str]:
    return {"role": "assistant", "content": content}, "stop"


class MockLLMServer:
    """`with MockLLMServer("normal") as m:` then use m.base_url as an OpenAI-compatible base URL."""

    def __init__(self, scenario: str = "normal"):
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown mock scenario {scenario!r}; choose from {SCENARIOS}")
        self.scenario = scenario
        self.requests: list[dict] = []
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.mock = self   # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}/v1"

    def __enter__(self) -> "MockLLMServer":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def _call(self, n: int, name: str, args: dict | str) -> tuple[dict, str]:
        return ({"role": "assistant", "content": None, "tool_calls": [{
            "id": f"call_mock_{n}", "type": "function",
            "function": {"name": name, "arguments": args if isinstance(args, str) else json.dumps(args)}}]},
            "tool_calls")

    def decide(self, messages: list[dict]) -> tuple[dict, str]:
        calls = _history(messages)
        n = len(calls) + 1
        user = next((m.get("content") for m in messages if m.get("role") == "user"), "") or ""
        found = re.search(r"alert_id=([A-Za-z0-9._:-]+)", user if isinstance(user, str) else json.dumps(user))
        alert_id = found.group(1) if found else "unknown"

        if not calls:
            if self.scenario == "no_submit":
                return _text("[MOCK] This looks like a brute-force attempt. (Scripted reply, no plan submitted.)")
            if self.scenario == "escape":
                return self._call(n, "terminal", {"command": f"touch {ESCAPE_MARKER}"})
            if self.scenario == "bad_args":
                return self._call(n, "get_alert", {"alert": alert_id, "extra": 1})
            return self._call(n, "get_alert", {"alert_id": alert_id})

        name, _, result = calls[-1]
        if name == "submit_investigation_plan" and _json(result).get("accepted") is True:
            return _text(FINAL_REPLY)
        alert = next((_json(r)["alert"] for nm, _, r in reversed(calls)
                      if nm == "get_alert" and isinstance(_json(r).get("alert"), dict)), None)
        if alert is None:
            if sum(nm == "get_alert" for nm, _, _ in calls) >= 3:
                return _text("[MOCK] Could not read the alert; giving up.")
            return self._call(n, "get_alert", {"alert_id": alert_id})
        submits = sum(nm == "submit_investigation_plan" for nm, _, _ in calls)
        if submits >= 3:
            return _text("[MOCK] Plan was rejected too often; giving up.")
        plan = build_mock_plan(alert)
        if self.scenario == "invalid_first" and submits == 0:
            plan["steps"][1]["parameters"] = {"src_ip": INVENTED_IP}
        if self.scenario == "string_plan" and submits == 0:      # one stray "}" as in the live run
            broken = json.dumps(plan).replace('}, "rationale"', '}}, "rationale"', 1)
            return self._call(n, "submit_investigation_plan", {"plan": broken})
        return self._call(n, "submit_investigation_plan", {"plan": plan})


class _Handler(BaseHTTPRequestHandler):
    server_version = "MockOpenAI/1.0"

    def log_message(self, *a) -> None:
        pass

    def _send(self, code: int, body: dict | str, content_type: str = "application/json") -> None:
        data = (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path.rstrip("/").endswith("/models") or self.path.rstrip("/").endswith(f"/models/{MOCK_MODEL}"):
            return self._send(200, {"object": "list", "data": [{"id": MOCK_MODEL, "object": "model",
                                                                "owned_by": "mock"}]})
        self._send(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:
        mock: MockLLMServer = self.server.mock  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length", 0))
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self.rfile.read(length)
            return self._send(404, {"error": {"message": "not found"}})
        body = _json(self.rfile.read(length).decode("utf-8", "replace"))
        mock.requests.append(body)
        if mock.scenario == "http_error":
            return self._send(500, {"error": {"message": "[MOCK] simulated upstream failure"}})
        message, finish = mock.decide(body.get("messages", []))
        cid, usage = f"mock-{len(mock.requests)}", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        if not body.get("stream"):
            return self._send(200, {"id": cid, "object": "chat.completion", "model": MOCK_MODEL, "usage": usage,
                                    "choices": [{"index": 0, "message": message, "finish_reason": finish}]})
        delta: dict = {"role": "assistant"}
        if message.get("content"):
            delta["content"] = message["content"]
        if message.get("tool_calls"):
            delta["tool_calls"] = [dict(tc, index=i) for i, tc in enumerate(message["tool_calls"])]
        chunks = [{"id": cid, "object": "chat.completion.chunk", "model": MOCK_MODEL,
                   "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                  {"id": cid, "object": "chat.completion.chunk", "model": MOCK_MODEL,
                   "choices": [{"index": 0, "delta": {}, "finish_reason": finish}], "usage": usage}]
        self._send(200, "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n",
                   "text/event-stream")
