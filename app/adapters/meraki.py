"""Cisco Meraki MX firewall adapter (Dashboard API v1).

Used when FIREWALL_MODE=meraki. A block becomes deny rules at the top of
each configured network's L3 outbound rules (traffic to the target) and,
if MERAKI_BLOCK_INBOUND is true, its inbound rules (traffic from the
target). Every rule's comment carries a tag naming the SOC action that
created it, so a retried execute is a no-op and a revert removes exactly
the rules this action added, never rules an administrator created.

Meraki only supports replacing a network's whole rule list, so every
update is a read-modify-write done under a PostgreSQL advisory lock per
network and rule set: two workers never overwrite each other's changes.
"""
import time
from ipaddress import ip_network

import requests

from .. import db
from ..config import settings

REQUEST_TIMEOUT = 10  # seconds
MAX_RATE_LIMIT_RETRIES = 3
DEFAULT_RULE_COMMENT = "Default rule"
OUTBOUND = "l3FirewallRules"
INBOUND = "inboundFirewallRules"




class MerakiError(Exception):
    pass




# Send Dashboard API requests with bounded rate-limit retries and timeouts.
def _request(method: str, path: str, body: dict | None = None) -> dict:
    url = settings.meraki_base_url.rstrip("/") + path
    headers = {
        "Authorization": f"Bearer {settings.meraki_api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    retries = 0
    while True:
        response = requests.request(method, url, headers=headers, json=body, timeout=REQUEST_TIMEOUT)
        if response.status_code == 429 and retries < MAX_RATE_LIMIT_RETRIES:
            # Meraki rate-limits per organization and says how long to wait.
            retries += 1
            try:
                wait_seconds = float(response.headers.get("Retry-After", 1))
            except ValueError:
                wait_seconds = 1
            time.sleep(min(max(wait_seconds, 1), 10))
            continue
        if not response.ok:
            raise MerakiError(
                f"{method} {path} returned HTTP {response.status_code}: {response.text[:300]}"
            )
        return response.json() if response.content else {}




# Build a stable tag used to find this action's rules during retries and reverts.
def _tag(command: dict) -> str:
    return f"[soc-action-{command['action_id']}]"




def _has_tag(rule: dict, tag: str) -> bool:
    return tag in (rule.get("comment") or "")




def _rulesets() -> list[str]:
    return [OUTBOUND, INBOUND] if settings.meraki_block_inbound else [OUTBOUND]




# Assemble provider-format deny-rule entries for supported block actions.
def _deny_rule(comment: str, protocol: str, src_cidr: str, dest_cidr: str, dest_port: str) -> dict:
    return {
        "comment": comment,
        "policy": "deny",
        "protocol": protocol,
        "srcCidr": src_cidr,
        "srcPort": "Any",
        "destCidr": dest_cidr,
        "destPort": dest_port,
    }




def _deny_rules(command: dict, ruleset: str) -> list[dict]:
    action_type = command["action_type"]
    target = command["target"]
    comment = f"{_tag(command)} AI-SOC {action_type} {target}"

    if action_type == "block_ip":
        cidr = str(ip_network(target, strict=False))
        if ruleset == OUTBOUND:
            return [_deny_rule(comment, "any", "Any", cidr, "Any")]
        return [_deny_rule(comment, "any", cidr, "Any", "Any")]

    if action_type == "block_port":
        port = str(int(target))
        return [_deny_rule(comment, protocol, "Any", "Any", port) for protocol in ("tcp", "udp")]

    raise MerakiError(f"Meraki adapter does not support action type '{action_type}'")




# Serialize read-modify-write updates so workers cannot overwrite each other.
def _update_rules(network_id: str, ruleset: str, change) -> None:
    """Apply change(rules) -> new rules (or None for "nothing to do")."""
    path = f"/networks/{network_id}/appliance/firewall/{ruleset}"
    with db.pool.connection() as conn:
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"meraki:{network_id}:{ruleset}",),
        )
        current = _request("GET", path)
        rules = list(current.get("rules", []))
        if rules and rules[-1].get("comment") == DEFAULT_RULE_COMMENT:
            rules.pop()  # Meraki appends the default rule itself; it must not be sent back

        updated = change(rules)
        if updated is None:
            return

        body = {"rules": updated}
        if "syslogDefaultRule" in current:
            body["syslogDefaultRule"] = current["syslogDefaultRule"]
        _request("PUT", path, body)




# Remove only rules carrying this action's tag from the current configured scope.
def _remove_tagged(tag: str) -> str | None:
    """Remove this action's rules everywhere. Returns an error message, or None."""

    def without_tag(rules: list[dict]) -> list[dict] | None:
        kept = [rule for rule in rules if not _has_tag(rule, tag)]
        return kept if len(kept) != len(rules) else None

    try:
        for network_id in settings.meraki_network_id_list:
            for ruleset in _rulesets():
                _update_rules(network_id, ruleset, without_tag)
    except (MerakiError, requests.RequestException) as error:
        return str(error)
    return None




# Apply the block across configured networks and clean up partial failures.
def execute(command: dict) -> tuple[bool, str]:
    """Add the deny rules on every configured network. Returns (success, message)."""
    tag = _tag(command)
    try:
        rules_by_set = {ruleset: _deny_rules(command, ruleset) for ruleset in _rulesets()}
    except (MerakiError, ValueError) as error:
        return False, f"Meraki block not attempted: {error}"

    networks = settings.meraki_network_id_list
    try:
        for network_id in networks:
            for ruleset, new_rules in rules_by_set.items():
                _update_rules(
                    network_id,
                    ruleset,
                    lambda rules, new_rules=new_rules: (
                        None if any(_has_tag(rule, tag) for rule in rules) else new_rules + rules
                    ),
                )
    except (MerakiError, requests.RequestException) as error:
        # Don't leave a half-applied block that the SOC can't see or revert:
        # the action is recorded as failed, so remove whatever was added.
        message = f"Meraki block failed: {error}"
        cleanup_error = _remove_tagged(tag)
        if cleanup_error:
            message += f"; removing partially applied rules also failed: {cleanup_error}"
        return False, message

    return True, (
        f"Meraki: {command['action_type']} {command['target']} applied on "
        f"{len(networks)} network(s)"
    )




# Reverse an action by removing its tagged rules.
def revert(command: dict) -> tuple[bool, str]:
    """Remove the rules this action added (unblock)."""
    error = _remove_tagged(_tag(command))
    if error:
        return False, f"Meraki unblock failed: {error}"
    return True, f"Meraki: removed {command['action_type']} rules for {command['target']}"
