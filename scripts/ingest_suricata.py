"""Tails a Suricata eve.json log and forwards each 'alert' event into the
AI-Driven SOC backend's /alerts/ingest endpoint.

Ported from the security team's suricata_reader.py, but instead of
writing to a local JSONL file, this posts straight into the real
pipeline — so Suricata alerts flow through the same tolerant ingestion,
correlation, and tier1 triage as everything else.

Run on the box where Suricata is writing eve.json:
    python ingest_suricata.py
    python ingest_suricata.py --replay          # read from the start, not just new lines
    python ingest_suricata.py --source /path/to/eve.json --backend http://192.168.1.10:8000
"""
import argparse
import os

DEFAULT_SOURCE = "/var/log/suricata/eve.json"
if __package__:
    from .ingest_common import follow_file, parse_json_line, send_alert
else:
    from ingest_common import follow_file, parse_json_line, send_alert
SEVERITY_MAP = {1: 1, 2: 3, 3: 5}


def normalize(event: dict) -> dict:
    """Map a Suricata eve.json alert event onto our AlertIn shape."""
    alert = event.get("alert") or {}
    return {
        "source": "ids",
        "event_time": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dest_ip"),
        "signature": alert.get("signature"),
        "severity": SEVERITY_MAP.get(alert.get("severity"), alert.get("severity")),
        # extra context kept in raw_event by our tolerant ingestion:
        "dest_port": event.get("dest_port"),
        "category": alert.get("category"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE, help="Path to Suricata's eve.json")
    parser.add_argument("--backend", default=os.environ.get("BACKEND_URL", "http://localhost:8000"))
    parser.add_argument("--api-key", default=os.environ.get("INGEST_API_KEY"))
    parser.add_argument("--replay", action="store_true", help="Read from the start of the file instead of only new lines")
    parser.add_argument("--state-file", help="Checkpoint file path (defaults to a per-source file under ~/.soc-ingest)")
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("Set INGEST_API_KEY (env var) or pass --api-key")

    print(f"Watching {args.source} -> {args.backend}/alerts/ingest")

    for line_number, (line, acknowledge, idempotency_key) in enumerate(
        follow_file(args.source, args.replay, args.state_file), 1
    ):
        event = parse_json_line(line, args.source, line_number)
        if event is None:
            acknowledge()
            continue

        if event.get("event_type") != "alert":
            acknowledge()
            continue

        send_alert(args.backend, args.api_key, normalize(event), idempotency_key)
        acknowledge()


if __name__ == "__main__":
    main()