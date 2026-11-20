# Logs (Day 2)

This folder will hold the evidence that the Day 2 `search_logs` tool reads. All files will be **synthetic lab data** (or Cehpoint-supplied samples), using the same scenario as the Day 1 alert: `j.mehta` on `fin-app-01` (10.20.5.17), source `203.0.113.77`, 2026-11-18 09:31:02–09:42:17 UTC. There are no log files yet on Day 1.

| Planned file | Source | What it shows |
|---|---|---|
| `wazuh_alerts.jsonl` | Wazuh `alerts.json` export (one JSON alert per line) | sshd authentication failures and the accepted login (the *outcome* of each attempt), plus events before and after: sudo, new users, other accounts targeted by the same IP |
| `tshark_sessions.csv` | tshark field export from a lab capture (`.pcapng`) | network sessions: time, source IP and port → destination IP and port, TCP stream id; used for connection volume and timing to port 22 and other connections after the login |

Command used to create `tshark_sessions.csv` from a lab capture (connection starts only, i.e. SYN without ACK):

```bash
tshark -r lab_capture.pcapng -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -E header=y -E separator=, -E quote=d \
  -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.stream \
  > data/logs/tshark_sessions.csv
```

**Why both sources:** SSH is encrypted, so tshark can show how many connections came from `203.0.113.77`, when, and to which hosts. It cannot show whether a password was right or wrong. Login success or failure comes from Wazuh / `auth.log`.
