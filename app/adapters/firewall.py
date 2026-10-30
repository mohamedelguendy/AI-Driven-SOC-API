"""Simulated firewall adapter, used when FIREWALL_MODE=simulated.

Reports what would be done without contacting any device, so the whole
approval -> execution -> expiry -> revert workflow can be demonstrated
safely. Real enforcement lives in secure_firewall.py (FIREWALL_MODE=fmc)
and meraki.py (FIREWALL_MODE=meraki).
"""




# Report the requested change without touching a real firewall.
def execute(command: dict) -> tuple[bool, str]:
    """Pretend to apply a block. Returns (success, message)."""
    return True, f"[SIMULATED] firewall: {command['action_type']} on {command['target']}"




# Report the reversal without touching a real firewall.
def revert(command: dict) -> tuple[bool, str]:
    """Pretend to remove a block (e.g. unblock an IP)."""
    return True, f"[SIMULATED] firewall: removed block on {command['target']}"
