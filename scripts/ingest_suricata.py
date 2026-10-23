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
import json
import os
import time

import requests

DEFAULT_SOURCE = "/var/log/suricata/eve.json"
POLL_INTERVAL = 0.5
REQUEST_TIMEOUT = 5


def normalize(event: dict) -> dict:
    """Map a Suricata eve.json alert event onto our AlertIn shape."""
    alert = event.get("alert") or {}
    return {
        "source": "ids",
        "event_time": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dest_ip"),
        "signature": alert.get("signature"),
        "severity": alert.get("severity"),  # Suricata: 1=high .. 3=low (passed through as-is)
        # extra context kept in raw_event by our tolerant ingestion:
        "dest_port": event.get("dest_port"),
        "category": alert.get("category"),
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
            print(f"[sent] {payload.get('signature')} -> {resp.json()}")
            return True
        print(f"[error] backend returned {resp.status_code}: {resp.text}")
        return False
    except requests.RequestException as e:
        print(f"[error] could not reach backend: {e}")
        return False


def follow(path: str, replay: bool):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        if not replay:
            f.seek(0, os.SEEK_END)  # live mode: skip historical events
        while True:
            line = f.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                # basic rotation handling: file got smaller than our position
                try:
                    if os.path.getsize(path) < f.tell():
                        f.seek(0)
                except OSError:
                    pass
                continue
            yield line


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE, help="Path to Suricata's eve.json")
    parser.add_argument("--backend", default=os.environ.get("BACKEND_URL", "http://localhost:8000"))
    parser.add_argument("--api-key", default=os.environ.get("INGEST_API_KEY"))
    parser.add_argument("--replay", action="store_true", help="Read from the start of the file instead of only new lines")
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("Set INGEST_API_KEY (env var) or pass --api-key")

    print(f"Watching {args.source} -> {args.backend}/alerts/ingest")

    for line in follow(args.source, args.replay):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        send_alert(args.backend, args.api_key, normalize(event))


if __name__ == "__main__":
    main()