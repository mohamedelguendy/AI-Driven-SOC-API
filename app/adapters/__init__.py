from ..config import settings
from . import edr, firewall, meraki

ADAPTERS = {"firewall": firewall, "edr": edr}


def _adapter_for(executor: str):
    if executor == "firewall" and settings.firewall_mode == "meraki":
        return meraki
    return ADAPTERS.get(executor)


def execute(executor: str, command: dict) -> tuple[bool, str]:
    """Routes a command to the right adapter's execute(). Never lets an
    adapter crash the request — a broken adapter becomes a failed
    action, not a 500 error.
    """
    adapter = _adapter_for(executor)
    if adapter is None:
        return False, f"No adapter configured for executor '{executor}'"
    try:
        return adapter.execute(command)
    except Exception as e:  # noqa: BLE001 — any adapter failure must become a logged failure, never a crash
        return False, f"Adapter error: {e}"


def revert(executor: str, command: dict) -> tuple[bool, str]:
    """Routes a command to the right adapter's revert() (unblock / un-isolate)."""
    adapter = _adapter_for(executor)
    if adapter is None:
        return False, f"No adapter configured for executor '{executor}'"
    try:
        return adapter.revert(command)
    except Exception as e:  # noqa: BLE001
        return False, f"Adapter error: {e}"
