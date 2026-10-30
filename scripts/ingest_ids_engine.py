"""Tails ids_alerts.jsonl (the output of the security team's ids_engine.py
— brute-force login and port-scan detection) and forwards each alert into
/alerts/ingest.

IMPORTANT — two things to know before running this alongside the other
feeders:

1. Overlap with ingest_suricata.py: ids_engine.py also re-emits Suricata
   alerts (as "SURICATA_ALERT") if it's fed suricata_events.jsonl. If you
   run BOTH ingest_suricata.py (reads eve.json directly) AND this script
   fed from an ids_engine.py that's also processing suricata_events.jsonl,
   Suricata alerts get ingested twice, as two separate alert rows.
   Fix: only feed ids_engine.py your custom events.jsonl (login/connection
   events), not suricata_events.jsonl — let ingest_suricata.py be the only
   path for Suricata alerts.

2. Re-run behavior: ids_engine.py's brute-force/port-scan counters are
   in-memory and reset every time it's run (it re-reads the whole input
   file from the start). Running it repeatedly on a growing events.jsonl
   can re-trigger the same threshold crossing and emit a duplicate alert
   each time. Run it once per batch of new events (e.g. truncate/rotate
   events.jsonl after each run), not on a tight loop.

Usage:
    python ingest_ids_engine.py --source /path/to/ids_alerts.jsonl
    python ingest_ids_engine.py --source /path/to/ids_alerts.jsonl --replay
"""
import argparse
import os

if __package__:
    from .ingest_common import follow_file, parse_json_line, send_alert
else:
    from ingest_common import follow_file, parse_json_line, send_alert

SEVERITY_MAP = {"LOW": 5, "MEDIUM": 3, "HIGH": 1}




# Map a custom IDS-engine record into the shared backend alert format.
def normalize(alert: dict) -> dict:
    return {
        "source": "ids",
        "event_time": alert.get("timestamp") or alert.get("source_timestamp"),
        "src_ip": alert.get("src_ip"),
        "dst_ip": alert.get("dest_ip"),
        "signature": alert.get("signature") or alert.get("alert_type"),
        "severity": SEVERITY_MAP.get(alert.get("severity"), 2),
        "description": alert.get("description"),
        "dest_port": alert.get("dest_port"),
        "engine": alert.get("engine"),
    }




# Tail the IDS output and forward each parsed event to the API.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Path to ids_alerts.jsonl")
    parser.add_argument("--backend", default=os.environ.get("BACKEND_URL", "http://localhost:8000"))
    parser.add_argument("--api-key", default=os.environ.get("INGEST_API_KEY"))
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--state-file", help="Checkpoint file path (defaults to a per-source file under ~/.soc-ingest)")
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("Set INGEST_API_KEY (env var) or pass --api-key")

    print(f"Watching {args.source} -> {args.backend}/alerts/ingest")

    for line_number, (line, acknowledge, idempotency_key) in enumerate(
        follow_file(args.source, args.replay, args.state_file), 1
    ):
        alert = parse_json_line(line, args.source, line_number)
        if alert is None:
            acknowledge()
            continue
        send_alert(args.backend, args.api_key, normalize(alert), idempotency_key)
        acknowledge()




if __name__ == "__main__":
    main()
