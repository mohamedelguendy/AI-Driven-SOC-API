"""Tails the EDR agent's edr_alerts.jsonl (from edr_agent.py /
edr_detection.py) and forwards each alert into /alerts/ingest.

Run this on the machine where edr_agent.py writes its alert log:
    python ingest_edr.py --source /path/to/edr_alerts.jsonl
    python ingest_edr.py --source /path/to/edr_alerts.jsonl --replay
"""
import argparse
import os

if __package__:
    from .ingest_common import follow_file, parse_json_line, send_alert
else:
    from ingest_common import follow_file, parse_json_line, send_alert

SEVERITY_MAP = {"LOW": 5, "MEDIUM": 3, "HIGH": 1}




# Convert an EDR record into the backend's shared alert event shape.
def normalize(alert: dict) -> dict:
    return {
        "source": "edr",
        "event_time": alert.get("timestamp"),
        "hostname": alert.get("hostname"),
        "signature": f"{alert.get('rule_id')}: {alert.get('rule_name')}",
        "severity": SEVERITY_MAP.get(alert.get("severity"), 2),
        "process_name": alert.get("process_name"),
        "path": alert.get("path"),
        "pid": alert.get("pid"),
        "description": alert.get("description"),
    }




# Validate CLI settings, tail the source file, and acknowledge delivered lines.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Path to edr_alerts.jsonl")
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
