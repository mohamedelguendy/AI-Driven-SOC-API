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
import json
import os
import time

import requests

POLL_INTERVAL = 0.5
REQUEST_TIMEOUT = 5

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
        "severity": 2,
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


def send_alert(backend_url: str, api_key: str, payload: dict) -> bool:
    try:
        resp = requests.post(
            f"{backend_url}/alerts/ingest",
            json=payload,
            headers={"X-API-Key": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            print(f"[sent] {payload['signature']} -> {resp.json()}")
            return True
        print(f"[error] backend returned {resp.status_code}: {resp.text}")
        return False
    except requests.RequestException as e:
        print(f"[error] could not reach backend: {e}")
        return False


def follow(path: str, replay: bool):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        if not replay:
            f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                try:
                    if os.path.getsize(path) < f.tell():
                        f.seek(0)
                except OSError:
                    pass
                continue
            yield line


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Path to Zeek's conn.log (JSON format)")
    parser.add_argument("--backend", default=os.environ.get("BACKEND_URL", "http://localhost:8000"))
    parser.add_argument("--api-key", default=os.environ.get("INGEST_API_KEY"))
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("Set INGEST_API_KEY (env var) or pass --api-key")

    print(f"Watching {args.source} -> {args.backend}/alerts/ingest "
          f"(forwarding only: {sorted(INTERESTING_STATES)})")

    for line in follow(args.source, args.replay):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not is_interesting(record):
            continue

        send_alert(args.backend, args.api_key, normalize(record))


if __name__ == "__main__":
    main()