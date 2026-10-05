"""Firewall adapter.
 
SIMULATED until the security team shares how the firewall is controlled
(its API, or SSH access). When that's available, replace the bodies of
execute() and revert() with the real calls — everything upstream
(approval, impact rules, allowlist, expiry, audit log) stays the same.
"""
 
 
def execute(command: dict) -> tuple[bool, str]:
    """Apply a block/allow rule. Returns (success, message)."""
    action = command["action_type"]
    target = command["target"]
 
    # --- real integration goes here, e.g. ---
    # try:
    #     response = requests.post(FIREWALL_API_URL, json={...}, timeout=5)
    #     return response.ok, response.text
    # except requests.RequestException as e:
    #     return False, f"Firewall unreachable: {e}"
 
    return True, f"[SIMULATED] firewall: {action} on {target}"
 
 
def revert(command: dict) -> tuple[bool, str]:
    """Undo a previously applied rule (e.g. unblock an IP)."""
    target = command["target"]
 
    # --- real integration goes here ---
 
    return True, f"[SIMULATED] firewall: removed block on {target}"
 