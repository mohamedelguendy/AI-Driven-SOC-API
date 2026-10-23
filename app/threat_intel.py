"""IP reputation lookups via AbuseIPDB (and VirusTotal, if configured).

Caches results in the database so the same IP isn't re-queried on every
alert. If no API key is set, lookups still succeed — they just report
'no_provider_configured' instead of a verdict, so the feature degrades
gracefully rather than breaking the alert pipeline.
"""
from datetime import timedelta

import requests
from psycopg.types.json import Jsonb

from .config import settings

CACHE_TTL = timedelta(hours=1)
REQUEST_TIMEOUT = 5  # seconds — never let a slow provider stall a request


def _query_virustotal(ip: str) -> dict:
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
        verdict = "malicious" if malicious > 0 else "suspicious" if suspicious > 0 else "clean"
        return {"status": "ok", "verdict": verdict, "details": stats}
    except (requests.RequestException, KeyError) as e:
        return {"status": "error", "verdict": "unknown", "details": {"error": str(e)}}


def _query_abuseipdb(ip: str) -> dict:
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
        return {"status": "ok", "verdict": verdict, "details": data}
    except requests.RequestException as e:
        return {"status": "error", "verdict": "unknown", "details": {"error": str(e)}}


def lookup_ip(conn, ip_address: str) -> dict:
    cached = conn.execute(
        """
        SELECT provider, status, verdict, details, queried_at
        FROM threat_intel_lookups
        WHERE ip_address = %s AND queried_at > now() - %s
        ORDER BY queried_at DESC LIMIT 1
        """,
        (ip_address, CACHE_TTL),
    ).fetchone()
    if cached:
        return {**cached, "cached": True}

    results = []
    for provider, key, query_fn in (
        ("abuseipdb", settings.abuseipdb_api_key, _query_abuseipdb),
        ("virustotal", settings.virustotal_api_key, _query_virustotal),
    ):
        if not key:
            result = {"provider": provider, "status": "no_provider_configured", "verdict": "unknown", "details": {}}
        else:
            result = {"provider": provider, **query_fn(ip_address)}

        conn.execute(
            """
            INSERT INTO threat_intel_lookups (ip_address, provider, status, verdict, details)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (ip_address, result["provider"], result["status"], result["verdict"], Jsonb(result["details"])),
        )
        results.append(result)

    return {"ip_address": ip_address, "results": results, "cached": False}