"""Tails the EDR agent's edr_alerts.jsonl (from edr_agent.py /
edr_detection.py) and forwards each alert into /alerts/ingest.

Run this on the machine where edr_agent.py writes its alert log:
    python ingest_edr.py --source /path/to/edr_alerts.jsonl
    python ingest_edr.py --source /path/to/edr_alerts.jsonl --replay
"""
import argparse
import json
import os
import time

import requests

POLL_INTERVAL = 0.5
REQUEST_TIMEOUT = 5

SEVERITY_MAP = {"LOW": 1, "MEDIUM": 3, "HIGH": 5}


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
    parser.add_argument("--source", required=True, help="Path to edr_alerts.jsonl")
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