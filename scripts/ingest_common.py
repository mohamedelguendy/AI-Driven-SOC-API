"""Shared durable file-tail and HTTP delivery helpers for alert feeders."""
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import requests

POLL_INTERVAL = 0.5
REQUEST_TIMEOUT = 5
MAX_RETRY_DELAY = 60


def _default_state_path(source: str) -> Path:
    digest = hashlib.sha256(str(Path(source).resolve()).encode("utf-8")).hexdigest()
    state_dir = Path.home() / ".soc-ingest"
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / f"{digest}.json"


def _file_identity(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return stat.st_dev, stat.st_ino


def _write_checkpoint(state_path: Path, identity: tuple[int, int], offset: int) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = state_path.with_suffix(state_path.suffix + ".tmp")
    temporary_path.write_text(
        json.dumps({"device": identity[0], "inode": identity[1], "offset": offset}),
        encoding="utf-8",
    )
    os.replace(temporary_path, state_path)


def follow_file(path: str, replay: bool, state_file: str | None = None):
    source_path = Path(path)
    state_path = Path(state_file) if state_file else _default_state_path(path)
    while not source_path.exists():
        time.sleep(POLL_INTERVAL)

    file = source_path.open("r", encoding="utf-8", errors="replace")
    identity = _file_identity(source_path)
    checkpoint = None
    if state_path.exists() and not replay:
        checkpoint = json.loads(state_path.read_text(encoding="utf-8"))
    if checkpoint and (checkpoint.get("device"), checkpoint.get("inode")) == identity:
        file.seek(checkpoint["offset"])
    elif checkpoint or replay:
        file.seek(0)
        _write_checkpoint(state_path, identity, 0)
    else:
        file.seek(0, os.SEEK_END)
        _write_checkpoint(state_path, identity, file.tell())

    try:
        while True:
            line_offset = file.tell()
            line = file.readline()
            if line:
                event_fingerprint = hashlib.sha256(
                    (
                        f"{source_path.resolve()}:{identity[0]}:{identity[1]}:"
                        f"{line_offset}:{hashlib.sha256(line.encode('utf-8')).hexdigest()}"
                    ).encode("utf-8")
                ).hexdigest()

                def acknowledge():
                    _write_checkpoint(state_path, identity, file.tell())

                yield line, acknowledge, event_fingerprint
                continue

            try:
                current_identity = _file_identity(source_path)
                current_size = source_path.stat().st_size
            except OSError:
                time.sleep(POLL_INTERVAL)
                continue

            if current_identity != identity:
                file.close()
                file = source_path.open("r", encoding="utf-8", errors="replace")
                identity = current_identity
                replacement_checkpoint = None
                if state_path.exists():
                    replacement_checkpoint = json.loads(state_path.read_text(encoding="utf-8"))
                if replacement_checkpoint and (
                    replacement_checkpoint.get("device"),
                    replacement_checkpoint.get("inode"),
                ) == identity:
                    file.seek(replacement_checkpoint["offset"])
                else:
                    file.seek(0)
                continue

            if current_size < file.tell():
                file.seek(0)
            time.sleep(POLL_INTERVAL)
    finally:
        file.close()


def parse_json_line(line: str, source: str, line_number: int):
    try:
        value = json.loads(line)
    except json.JSONDecodeError as error:
        print(
            f"[error] {source}:{line_number}: invalid JSON at column {error.colno}: {error.msg}",
            file=sys.stderr,
        )
        return None
    if not isinstance(value, dict):
        print(f"[error] {source}:{line_number}: expected a JSON object", file=sys.stderr)
        return None
    return value


def send_alert(
    backend_url: str,
    api_key: str,
    payload: dict,
    idempotency_key: str,
) -> bool:
    delay = 1
    while True:
        try:
            response = requests.post(
                f"{backend_url.rstrip('/')}/alerts/ingest",
                json=payload,
                headers={
                    "X-API-Key": api_key,
                    "Idempotency-Key": idempotency_key,
                },
                timeout=REQUEST_TIMEOUT,
            )
            if 200 <= response.status_code < 300:
                print(f"[sent] {payload.get('signature')} -> {response.status_code}")
                return True

            if response.status_code not in (408, 425, 429) and response.status_code < 500:
                raise RuntimeError(
                    f"Backend rejected alert with HTTP {response.status_code}: {response.text}"
                )
            retry_after = response.headers.get("Retry-After")
            try:
                server_delay = int(retry_after or 0)
            except ValueError:
                server_delay = 0
            wait_seconds = min(MAX_RETRY_DELAY, max(delay, server_delay))
            print(
                f"[retry] backend returned HTTP {response.status_code}; "
                f"retrying in {wait_seconds}s",
                file=sys.stderr,
            )
        except requests.RequestException as error:
            wait_seconds = delay
            print(f"[retry] backend unavailable ({error}); retrying in {wait_seconds}s", file=sys.stderr)

        time.sleep(wait_seconds)
        delay = min(delay * 2, MAX_RETRY_DELAY)
