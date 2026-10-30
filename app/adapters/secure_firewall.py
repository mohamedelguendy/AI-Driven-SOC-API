"""Cisco Secure Firewall adapter, through the Firewall Management Center
(FMC) REST API.

Used when FIREWALL_MODE=fmc. A block is an IP mapping in an FMC dynamic
object (FMC 7.0+). An administrator creates that object once, references
it in Block rules at the top of the access control policy, and deploys
once. After that, adding or removing an IP takes effect on the firewalls
without another deployment, so the SOC never deploys policy and never
pushes anyone else's pending changes.

Give the SOC its own dynamic object: a revert removes the IP from the
object even if someone also added it by hand.
"""
import threading
import time
from ipaddress import ip_network

import requests

from ..config import settings

REQUEST_TIMEOUT = 15  # seconds
TOKEN_LIFETIME_SECONDS = 25 * 60  # FMC tokens last 30 minutes; renew early
MAX_RATE_LIMIT_RETRIES = 3
PAGE_LIMIT = 1000




class FMCError(Exception):
    pass




_lock = threading.Lock()
_session = {"token": None, "domain": None, "issued_at": 0.0, "object_id": None, "object_name": None}




# Choose TLS certificate verification settings for FMC requests.
def _verify():
    return settings.fmc_ca_bundle or settings.fmc_verify_tls




# Request an FMC access token and its domain ID using the configured account.
def _authenticate() -> None:
    response = requests.post(
        f"{settings.fmc_host.rstrip('/')}/api/fmc_platform/v1/auth/generatetoken",
        auth=(settings.fmc_username, settings.fmc_password),
        verify=_verify(),
        timeout=REQUEST_TIMEOUT,
    )
    token = response.headers.get("X-auth-access-token")
    domain = response.headers.get("DOMAIN_UUID")
    if response.status_code != 204 or not token or not domain:
        raise FMCError(f"FMC login failed with HTTP {response.status_code}")
    _session.update(token=token, domain=domain, issued_at=time.monotonic())




# Bound how long FMC asks clients to wait before retrying.
def _retry_after(response) -> float:
    try:
        return min(max(float(response.headers.get("Retry-After", 2)), 1), 30)
    except ValueError:
        return 2




# Centralize authenticated requests, token refresh, and rate-limit handling.
def _request(method: str, path: str, body: dict | None = None, params: dict | None = None) -> dict:
    """Call an FMC config endpoint. path is relative to the domain URL."""
    with _lock:
        if _session["token"] is None or time.monotonic() - _session["issued_at"] > TOKEN_LIFETIME_SECONDS:
            _authenticate()
        reauthenticated = False
        retries = 0
        while True:
            response = requests.request(
                method,
                f"{settings.fmc_host.rstrip('/')}/api/fmc_config/v1/domain/{_session['domain']}{path}",
                headers={
                    "X-auth-access-token": _session["token"],
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json=body,
                params=params,
                verify=_verify(),
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 401 and not reauthenticated:
                reauthenticated = True  # token expired or was revoked
                _authenticate()
                continue
            if response.status_code == 429 and retries < MAX_RATE_LIMIT_RETRIES:
                retries += 1
                time.sleep(_retry_after(response))
                continue
            if not response.ok:
                raise FMCError(
                    f"{method} {path} returned HTTP {response.status_code}: {response.text[:300]}"
                )
            return response.json() if response.content else {}




# Find the SOC-owned dynamic object used by the mapping helpers below.
def _dynamic_object_id() -> str:
    name = settings.fmc_dynamic_object
    if _session["object_id"] and _session["object_name"] == name:
        return _session["object_id"]

    result = _request("GET", "/object/dynamicobjects", params={"name": name})
    matches = [item for item in result.get("items", []) if item.get("name") == name]
    if not matches:
        raise FMCError(
            f"Dynamic object '{name}' was not found on the FMC; create it and "
            "reference it in Block rules (see README)"
        )
    _session.update(object_id=matches[0]["id"], object_name=name)
    return matches[0]["id"]




# Canonicalize an address so equivalent host and subnet values compare equally.
def _normalize(address: str) -> str:
    network = ip_network(address, strict=False)
    return str(network.network_address) if network.num_addresses == 1 else str(network)




# Read every mapping page while retaining the exact strings FMC expects on removal.
def _mappings(object_id: str) -> dict[str, list[str]]:
    """Normalized address -> the exact strings the FMC stores for it
    (e.g. "203.0.113.7" may be stored as "203.0.113.7/32")."""
    found: dict[str, list[str]] = {}
    offset = 0
    while True:
        page = _request(
            "GET",
            f"/object/dynamicobjects/{object_id}/mappings",
            params={"limit": PAGE_LIMIT, "offset": offset},
        )
        items = page.get("items", [])
        for item in items:
            try:
                found.setdefault(_normalize(item["mapping"]), []).append(item["mapping"])
            except (KeyError, ValueError):
                continue
        if not items or "next" not in page.get("paging", {}):
            return found
        offset += len(items)




# Validate the action type and canonicalize its target IP/CIDR.
def _target(command: dict) -> str:
    if command["action_type"] != "block_ip":
        raise FMCError(
            f"the Secure Firewall adapter supports block_ip only, not '{command['action_type']}'"
        )
    return _normalize(command["target"])




# Build the FMC request body for adding or removing mappings.
def _change_mapping(object_id: str, operation: str, addresses: list[str]) -> None:
    if settings.firewall_execution_mode == "dry_run":
        return  # everything up to the write has run; the firewall stays untouched
    body = {"add": [], "remove": []}
    body[operation] = [{"mappings": addresses, "dynamicObject": {"id": object_id}}]
    _request("POST", "/object/dynamicobjectmappings", body)




# Add a supported target to the configured dynamic object idempotently.
def execute(command: dict) -> tuple[bool, str]:
    """Add the target IP to the SOC's dynamic object. Returns (success, message)."""
    try:
        target = _target(command)
    except (FMCError, ValueError) as error:
        return False, f"Secure Firewall block not attempted: {error}"

    name = settings.fmc_dynamic_object
    try:
        object_id = _dynamic_object_id()
        if target in _mappings(object_id):
            return True, f"Secure Firewall: {target} is already in dynamic object '{name}'"
        _change_mapping(object_id, "add", [target])
    except (FMCError, requests.RequestException) as error:
        _session["object_id"] = None  # look the object up again next time
        return False, f"Secure Firewall block failed: {error}"
    return True, f"Secure Firewall: added {target} to dynamic object '{name}'"




# Remove the target mapping to reverse a prior block.
def revert(command: dict) -> tuple[bool, str]:
    """Remove the target IP from the SOC's dynamic object (unblock)."""
    try:
        target = _target(command)
    except (FMCError, ValueError) as error:
        return False, f"Secure Firewall unblock not attempted: {error}"

    name = settings.fmc_dynamic_object
    try:
        object_id = _dynamic_object_id()
        stored = _mappings(object_id).get(target)
        if not stored:
            return True, f"Secure Firewall: {target} was already absent from dynamic object '{name}'"
        _change_mapping(object_id, "remove", stored)
    except (FMCError, requests.RequestException) as error:
        _session["object_id"] = None
        return False, f"Secure Firewall unblock failed: {error}"
    return True, f"Secure Firewall: removed {target} from dynamic object '{name}'"
