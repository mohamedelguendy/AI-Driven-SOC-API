from ipaddress import ip_address as parse_ip

from fastapi import APIRouter, Depends, HTTPException

from ..db import pool
from ..deps import get_current_user
from ..threat_intel import lookup_ip

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


@router.get("/{ip}")
def get_lookup(ip: str, user: dict = Depends(get_current_user)):
    try:
        parse_ip(ip)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid IP address")

    with pool.connection() as conn:
        return lookup_ip(conn, ip)


@router.get("")
def list_lookups(limit: int = 50, user: dict = Depends(get_current_user)):
    limit = max(1, min(limit, 200))
    with pool.connection() as conn:
        return conn.execute(
            "SELECT * FROM threat_intel_lookups ORDER BY queried_at DESC LIMIT %s",
            (limit,),
        ).fetchall()