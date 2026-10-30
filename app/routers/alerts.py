from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Header
from psycopg.types.json import Jsonb

from ..config import settings
from ..db import pool
from ..schemas import AlertIn
from ..security import verify_api_key

router = APIRouter(prefix="/alerts", tags=["alerts"])

VALID_SOURCES = {"siem", "ids", "edr", "firewall", "webapp"}

# Alerts sharing a src_ip get grouped into the same open incident if the
# newest one there is within this window. Keeps related events together
# without needing real correlation logic yet.
CORRELATION_WINDOW_MINUTES = 30

# Incident severity runs 1 (most severe) to 5. Used when an alert has none.
DEFAULT_INCIDENT_SEVERITY = 3


def _check_ingest_key(x_api_key: str | None = Header(default=None)):
    """Machine-to-machine auth for the security team's pipeline.

    Separate from user login (/auth/login) on purpose: the SIEM is a
    service, not a person with a tier2/tier3/admin role.
    """
    if not verify_api_key(x_api_key, settings.ingest_api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _safe_ip(value: Any) -> tuple[str | None, str | None]:
    """Returns (valid_ip_or_None, note_if_invalid)."""
    if value is None or value == "":
        return None, None
    try:
        ip_address(value if isinstance(value, str) else "")
        return value, None
    except ValueError:
        return None, f'"{value}" is not a valid IP'


def _safe_time(value: Any) -> tuple[datetime | None, str | None]:
    if value is None or value == "":
        return None, None
    try:
        if not isinstance(value, str):
            raise ValueError
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed, None
    except ValueError:
        return None, f'"{value}" is not a valid ISO timestamp'


def _safe_severity(value: Any) -> tuple[int | None, str | None]:
    if value is None:
        return None, None
    if isinstance(value, str) and value.strip().lstrip("-").isascii() and value.strip().lstrip("-").isdigit():
        value = int(value.strip())
    if type(value) is not int:  # bool is excluded on purpose
        return None, f'severity "{value}" is not an integer'
    if not -32768 <= value <= 32767:
        return None, f'severity "{value}" is outside the supported integer range'
    return value, None


def _safe_text(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    return str(value)


@router.post("/ingest", dependencies=[Depends(_check_ingest_key)])
def ingest_alert(
    alert: AlertIn,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    """Receive one security event. Never rejects a payload for missing or
    malformed fields — always stores raw_event, and marks what it could
    not parse.
    """
    notes: list[str] = []

    if isinstance(alert.source, str) and alert.source in VALID_SOURCES:
        source = alert.source
    else:
        notes.append(
            "missing source, defaulting to \"siem\""
            if alert.source is None
            else f'unknown source "{alert.source}", defaulting to "siem"'
        )
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

    severity, note = _safe_severity(alert.severity)
    if note:
        notes.append(note)

    hostname = _safe_text(alert.hostname)
    signature = _safe_text(alert.signature)

    parse_status = "failed" if not any([event_time, src_ip, dst_ip, hostname]) else (
        "partial" if notes else "ok"
    )
    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip()
    if idempotency_key == "":
        raise HTTPException(status_code=422, detail="Idempotency-Key must not be empty")
    if idempotency_key is not None and len(idempotency_key) > 255:
        raise HTTPException(status_code=422, detail="Idempotency-Key must be 255 characters or fewer")

    incident_severity = (
        min(max(severity, 1), 5) if severity is not None else DEFAULT_INCIDENT_SEVERITY
    )

    with pool.connection() as conn:
        if idempotency_key:
            conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"alert-idempotency:{idempotency_key}",),
            )
            existing = conn.execute(
                """
                SELECT id, incident_id, parse_status, parse_notes, raw_event
                FROM alerts
                WHERE source_event_id = %s
                """,
                (idempotency_key,),
            ).fetchone()
            if existing:
                if existing["raw_event"] != alert.model_dump():
                    raise HTTPException(
                        status_code=409,
                        detail="Idempotency-Key was already used for a different alert payload",
                    )
                conn.execute(
                    """
                    INSERT INTO audit_log
                        (actor_type, event_type, entity_type, entity_id, details)
                    VALUES ('system', 'alert.ingest_duplicate', 'alert', %s, %s)
                    """,
                    (
                        existing["id"],
                        Jsonb({"source_event_id": idempotency_key}),
                    ),
                )
                return {
                    "alert_id": existing["id"],
                    "incident_id": existing["incident_id"],
                    "parse_status": existing["parse_status"],
                    "parse_notes": existing["parse_notes"].split("; ")
                    if existing["parse_notes"]
                    else [],
                    "duplicate": True,
                }

        # Correlate: attach to a recent unresolved incident from the same
        # src_ip (including ones already escalated or in response),
        # otherwise open a new one.
        incident_id = None
        if src_ip:
            conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"alert-correlation:{src_ip}",),
            )
            row = conn.execute(
                """
                SELECT i.id FROM incidents i
                JOIN alerts a ON a.incident_id = i.id
                WHERE a.src_ip = %s
                  AND i.status IN ('new', 'investigating', 'escalated', 'in_response')
                  AND COALESCE(a.event_time, a.ingested_at) > now() - (%s || ' minutes')::interval
                  AND COALESCE(a.event_time, a.ingested_at) <= now() + interval '5 minutes'
                ORDER BY COALESCE(a.event_time, a.ingested_at) DESC
                LIMIT 1
                """,
                (src_ip, CORRELATION_WINDOW_MINUTES),
            ).fetchone()
            if row:
                incident_id = row["id"]
                if severity is not None:
                    # A more severe alert raises the incident's severity (1 is most severe).
                    conn.execute(
                        """
                        UPDATE incidents SET severity = %s, updated_at = now()
                        WHERE id = %s AND severity > %s
                        """,
                        (incident_severity, incident_id, incident_severity),
                    )

        if incident_id is None:
            incident = conn.execute(
                """
                INSERT INTO incidents (title, severity)
                VALUES (%s, %s)
                RETURNING id
                """,
                (
                    signature or f"{source} alert" + (f" from {src_ip}" if src_ip else ""),
                    incident_severity,
                ),
            ).fetchone()
            incident_id = incident["id"]

        row = conn.execute(
            """
            INSERT INTO alerts
                (incident_id, source_event_id, source, event_time, src_ip, dst_ip, hostname,
                 signature, severity, parse_status, parse_notes, raw_event)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                incident_id,
                idempotency_key,
                source,
                event_time,
                src_ip,
                dst_ip,
                hostname,
                signature,
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
        "duplicate": False,
    }
