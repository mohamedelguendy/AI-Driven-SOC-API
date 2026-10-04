from datetime import datetime, timezone
from ipaddress import ip_address

from fastapi import APIRouter, Depends, HTTPException, Header
from psycopg.types.json import Jsonb

from ..config import settings
from ..db import pool
from ..deps import get_current_user
from ..schemas import AlertIn

router = APIRouter(prefix="/alerts", tags=["alerts"])

VALID_SOURCES = {"siem", "ids", "edr", "firewall", "webapp"}

# Alerts sharing a src_ip get grouped into the same open incident if the
# newest one there is within this window. Keeps related events together
# without needing real correlation logic yet.
CORRELATION_WINDOW_MINUTES = 30


def _check_ingest_key(x_api_key: str | None = Header(default=None)):
    """Machine-to-machine auth for the security team's pipeline.

    Separate from user login (/auth/login) on purpose: the SIEM is a
    service, not a person with a tier2/tier3/admin role.
    """
    if x_api_key != settings.ingest_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _safe_ip(value: str | None) -> tuple[str | None, str | None]:
    """Returns (valid_ip_or_None, note_if_invalid)."""
    if not value:
        return None, None
    try:
        ip_address(value)
        return value, None
    except ValueError:
        return None, f'"{value}" is not a valid IP'


def _safe_time(value: str | None) -> tuple[datetime | None, str | None]:
    if not value:
        return None, None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")), None
    except ValueError:
        return None, f'"{value}" is not a valid ISO timestamp'


@router.post("/ingest", dependencies=[Depends(_check_ingest_key)])
def ingest_alert(alert: AlertIn):
    """Receive one security event. Never rejects a payload outright —
    always stores raw_event, and marks what it could not parse.
    """
    notes: list[str] = []

    source = alert.source if alert.source in VALID_SOURCES else None
    if source is None:
        notes.append(f'unknown source "{alert.source}", defaulting to "siem"')
        source = "siem"

    event_time, note = _safe_time(alert.event_time)
    if note:
        notes.append(note)

    src_ip, note = _safe_ip(alert.src_ip)
    if note:
        notes.append(note)

    dst_ip, note = _safe_ip(alert.dst_ip)
    if note:
        notes.append(note)

    severity = alert.severity if isinstance(alert.severity, int) else None
    if alert.severity is not None and severity is None:
        notes.append(f'severity "{alert.severity}" is not an integer')

    parse_status = "failed" if not any([event_time, src_ip, dst_ip, alert.hostname]) else (
        "partial" if notes else "ok"
    )

    with pool.connection() as conn:
        # Correlate: attach to a recent open incident from the same src_ip,
        # otherwise open a new one.
        incident_id = None
        if src_ip:
            row = conn.execute(
                """
                SELECT i.id FROM incidents i
                JOIN alerts a ON a.incident_id = i.id
                WHERE a.src_ip = %s
                  AND i.status IN ('new', 'investigating')
                  AND a.event_time > now() - (%s || ' minutes')::interval
                ORDER BY a.event_time DESC
                LIMIT 1
                """,
                (src_ip, CORRELATION_WINDOW_MINUTES),
            ).fetchone()
            if row:
                incident_id = row["id"]

        if incident_id is None:
            incident = conn.execute(
                """
                INSERT INTO incidents (title, severity)
                VALUES (%s, %s)
                RETURNING id
                """,
                (
                    alert.signature or f"{source} alert" + (f" from {src_ip}" if src_ip else ""),
                    severity or 1,
                ),
            ).fetchone()
            incident_id = incident["id"]

        row = conn.execute(
            """
            INSERT INTO alerts
                (incident_id, source, event_time, src_ip, dst_ip, hostname,
                 signature, severity, parse_status, parse_notes, raw_event)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                incident_id,
                source,
                event_time,
                src_ip,
                dst_ip,
                alert.hostname,
                alert.signature,
                severity,
                parse_status,
                "; ".join(notes) or None,
                Jsonb(alert.model_dump()),
            ),
        ).fetchone()

        conn.execute(
            """
            INSERT INTO audit_log (actor_type, event_type, entity_type, entity_id, details)
            VALUES ('system', 'alert.ingested', 'alert', %s, %s)
            """,
            (row["id"], Jsonb({"parse_status": parse_status, "incident_id": incident_id})),
        )

    return {
        "alert_id": row["id"],
        "incident_id": incident_id,
        "parse_status": parse_status,
        "parse_notes": notes,
    }