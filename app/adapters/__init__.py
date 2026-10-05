from . import edr, firewall
 
ADAPTERS = {"firewall": firewall, "edr": edr}
 
 
def execute(executor: str, command: dict) -> tuple[bool, str]:
    """Routes a command to the right adapter's execute(). Never lets an
    adapter crash the request — a broken adapter becomes a failed
    action, not a 500 error.
    """
    adapter = ADAPTERS.get(executor)
    if adapter is None:
        return False, f"No adapter configured for executor '{executor}'"
    try:
        return adapter.execute(command)
    except Exception as e:  # noqa: BLE001 — any adapter failure must become a logged failure, never a crash
        return False, f"Adapter error: {e}"
 
 
def revert(executor: str, command: dict) -> tuple[bool, str]:
    """Routes a command to the right adapter's revert() (unblock / un-isolate)."""
    adapter = ADAPTERS.get(executor)
    if adapter is None:
        return False, f"No adapter configured for executor '{executor}'"
    try:
        return adapter.revert(command)
    except Exception as e:  # noqa: BLE001
        return False, f"Adapter error: {e}"
 