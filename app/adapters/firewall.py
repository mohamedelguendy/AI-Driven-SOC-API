"""Firewall adapter.
 
SIMULATED until the security team shares how the firewall is controlled
(its API, or SSH access). When that's available, replace the body of
execute() with the real call — everything upstream (approval, impact
rules, allowlist, audit log) stays exactly the same.
"""
 
 
def execute(command: dict) -> tuple[bool, str]:
    action = command["action_type"]
    target = command["target"]
 
    # --- real integration goes here, e.g. ---
    # response = requests.post(FIREWALL_API_URL, json={...})
    # return response.ok, response.text
 
    return True, f"[SIMULATED] firewall: {action} on {target}"
 