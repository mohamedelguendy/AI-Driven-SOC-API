"""Tails a Zeek conn.log (JSON format) and forwards connections into the
AI-Driven SOC backend's /alerts/ingest endpoint.

Zeek's conn.log isn't itself an "alert" — it's a record of every
connection. This script only forwards connections that look worth a
second look (filtered below), not every DNS lookup on the network.
Adjust the filter to match what your team actually wants flagged.

Run on the box where Zeek is writing its logs:
    python ingest_zeek.py --source /path/to/conn.log
    python ingest_zeek.py --source /path/to/conn.log --replay
"""
import argparse
import os

if __package__:
    from .ingest_common import follow_file, parse_json_line, send_alert
else:
    from ingest_common import follow_file, parse_json_line, send_alert

# Only forward connections matching one of these — otherwise conn.log is
# far too noisy (every DNS lookup, every normal web request) to treat as
# alerts. Extend this as your detection needs grow.
INTERESTING_STATES = {"S0", "REJ", "RSTO", "RSTR"}  # failed/rejected/reset connections


def is_interesting(record: dict) -> bool:
    return record.get("conn_state") in INTERESTING_STATES


def normalize(record: dict) -> dict:
    return {
        "source": "ids",
        "event_time": _ts_to_iso(record.get("ts")),
        "src_ip": record.get("id.orig_h"),
        "dst_ip": record.get("id.resp_h"),
        "signature": f"Zeek: {record.get('conn_state')} connection "
                     f"({record.get('proto', '?')}/{record.get('service') or 'unknown'}) "
                     f"to port {record.get('id.resp_p')}",
        "severity": 3,
        "dest_port": record.get("id.resp_p"),
        "duration": record.get("duration"),
    }


def _ts_to_iso(ts):
    """Zeek timestamps are unix epoch floats; keep as-is if conversion fails
    (ingestion is tolerant of a non-ISO event_time — it just logs a note)."""
    if ts is None:
        return None
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        return str(ts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Path to Zeek's conn.log (JSON format)")
    parser.add_argument("--backend", default=os.environ.get("BACKEND_URL", "http://localhost:8000"))
    parser.add_argument("--api-key", default=os.environ.get("INGEST_API_KEY"))
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--state-file", help="Checkpoint file path (defaults to a per-source file under ~/.soc-ingest)")
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("Set INGEST_API_KEY (env var) or pass --api-key")

    print(f"Watching {args.source} -> {args.backend}/alerts/ingest "
          f"(forwarding only: {sorted(INTERESTING_STATES)})")

    for line_number, (line, acknowledge, idempotency_key) in enumerate(
        follow_file(args.source, args.replay, args.state_file), 1
    ):
        record = parse_json_line(line, args.source, line_number)
        if record is None:
            acknowledge()
            continue

        if not is_interesting(record):
            acknowledge()
            continue

        send_alert(args.backend, args.api_key, normalize(record), idempotency_key)
        acknowledge()


if __name__ == "__main__":
    main()