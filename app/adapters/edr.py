"""EDR adapter (endpoint detection & response).

SIMULATED until the security team shares the EDR's API details (e.g.
CrowdStrike, Microsoft Defender for Endpoint). Replace the bodies of
execute() and revert() with the real calls — everything upstream stays
the same.
"""




# Simulate endpoint isolation until an organization-specific EDR API is configured.
def execute(command: dict) -> tuple[bool, str]:
    """Isolate a host. Returns (success, message)."""
    action = command["action_type"]
    target = command["target"]  # hostname / endpoint ID
    if action == "isolate_host":
        return True, f"[SIMULATED] EDR: isolated host '{target}' from the network"
    return True, f"[SIMULATED] EDR: {action} on {target}"




# Simulate releasing an endpoint; no external device is contacted here.
def revert(command: dict) -> tuple[bool, str]:
    """Release a host from isolation."""
    return True, f"[SIMULATED] EDR: released host '{command['target']}' from isolation"
