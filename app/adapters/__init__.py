from . import edr, firewall
 
ADAPTERS = {"firewall": firewall, "edr": edr}
 
 
def execute(executor: str, command: dict) -> tuple[bool, str]:
    """Routes a command to the right adapter. Both adapters simulate for
    now — swap either one's execute() body for a real call once that
    team shares access details. Nothing else in the app needs to change.
    """
    adapter = ADAPTERS.get(executor)
    if adapter is None:
        return False, f"No adapter configured for executor '{executor}'"
    return adapter.execute(command)
 