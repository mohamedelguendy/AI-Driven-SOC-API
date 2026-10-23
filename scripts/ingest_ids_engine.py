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
import json
import os
import time

import requests

POLL_INTERVAL = 0.5
REQUEST_TIMEOUT = 5

SEVERITY_MAP = {"LOW": 5, "MEDIUM": 3, "HIGH": 1}


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
    parser.add_argument("--source", required=True, help="Path to ids_alerts.jsonl")
    parser.add_argument("--backend", default=os.environ.get("BACKEND_URL", "http://localhost:8000"))
    parser.add_argument("--api-key", default=os.environ.get("INGEST_API_KEY"))
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("Set INGEST_API_KEY (env var) or pass --api-key")

    print(f"Watching {args.source} -> {args.backend}/alerts/ingest")

    for line in follow(args.source, args.replay):
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue
        send_alert(args.backend, args.api_key, normalize(alert))


if __name__ == "__main__":
    main()