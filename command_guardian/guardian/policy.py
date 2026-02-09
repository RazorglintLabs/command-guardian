"""Policy engine — deny-by-default with always-block and risky rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from . import classifier as C

# ---------------------------------------------------------------------------
# Decision enum
# ---------------------------------------------------------------------------

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


# ---------------------------------------------------------------------------
# Block rules (always deny, no override)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _BlockRule:
    description: str
    pattern: re.Pattern[str]


_ALWAYS_BLOCK: list[_BlockRule] = [
    # Root deletion
    _BlockRule(
        "Destructive root deletion (rm -rf /)",
        re.compile(r"""\brm\s+.*-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+/\s*$""", re.I),
    ),
    _BlockRule(
        "Destructive root deletion (rm -rf /)",
        re.compile(r"""\brm\s+.*-[A-Za-z]*f[A-Za-z]*r[A-Za-z]*\s+/\s*$""", re.I),
    ),
    _BlockRule(
        "Destructive root deletion (rm -rf /*)",
        re.compile(r"""\brm\s+.*-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+/\*""", re.I),
    ),
    # curl/wget pipe to shell
    _BlockRule(
        "Network download piped to shell execution (curl|wget … | bash/sh)",
        re.compile(r"""(curl|wget)\s+.*\|\s*(ba)?sh""", re.I),
    ),
    # PowerShell download-and-execute
    _BlockRule(
        "PowerShell download-and-execute pattern",
        re.compile(r"""powershell\s+.*(\biex\b|\bInvoke-Expression\b)""", re.I),
    ),
    _BlockRule(
        "PowerShell download-and-execute pattern",
        re.compile(r"""(iwr|Invoke-WebRequest)\s+.*\|\s*(iex|Invoke-Expression)""", re.I),
    ),
    # Disk format commands
    _BlockRule(
        "Disk formatting command (mkfs/format/diskpart)",
        re.compile(r"""(^|\s)(mkfs|diskpart)\b""", re.I),
    ),
    _BlockRule(
        "Disk formatting command (format drive)",
        re.compile(r"""\bformat\s+[A-Za-z]\:""", re.I),
    ),
    # Destructive dd to device
    _BlockRule(
        "Destructive device write (dd … of=/dev/…)",
        re.compile(r"""\bdd\b.*\bof=/dev/""", re.I),
    ),
]

# ---------------------------------------------------------------------------
# Risky intents (require explicit authorization)
# ---------------------------------------------------------------------------

RISKY_INTENTS: set[str] = {
    C.FILE_DELETE,
    C.PRIVILEGE_ESCALATION,
    C.PROCESS_KILL,
    C.SYSTEM_CONFIG,
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str
    requires_auth: bool = False
    suggestion: str | None = None


def evaluate(command: str, intent: str) -> PolicyResult:
    """Evaluate *command* with classified *intent* and return a ``PolicyResult``.

    Returns DENY for always-block patterns.
    Returns DENY with ``requires_auth=True`` for risky intents (caller must
    handle interactive confirmation or token resolution).
    Returns ALLOW for everything else.
    """
    # Gate 1: always-block patterns
    for rule in _ALWAYS_BLOCK:
        if rule.pattern.search(command):
            return PolicyResult(
                decision=Decision.DENY,
                reason=f"BLOCKED: {rule.description}",
                suggestion=_suggestion_for(rule.description),
            )

    # Gate 2: risky intents need authorization
    if intent in RISKY_INTENTS:
        return PolicyResult(
            decision=Decision.DENY,
            reason=f"Risky intent ({intent}) requires explicit authorization.",
            requires_auth=True,
            suggestion=_suggestion_for_intent(intent, command),
        )

    # Gate 3: safe
    return PolicyResult(decision=Decision.ALLOW, reason="Command allowed by policy.")


def get_block_rules_summary() -> list[str]:
    return [r.description for r in _ALWAYS_BLOCK]


def get_risky_intents() -> list[str]:
    return sorted(RISKY_INTENTS)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _suggestion_for(description: str) -> str | None:
    if "root deletion" in description.lower():
        return "Delete specific paths instead: rm -rf ./my_folder"
    if "pipe" in description.lower() or "download" in description.lower():
        return "Download the script first, review it, then run: curl -O script.sh && cat script.sh && bash script.sh"
    if "format" in description.lower() or "diskpart" in description.lower():
        return "Use safe disk utilities with explicit confirmation."
    if "dd" in description.lower() or "device write" in description.lower():
        return "Double-check the target device; use a file path instead of a block device."
    return None


def _suggestion_for_intent(intent: str, command: str) -> str | None:
    if intent == C.FILE_DELETE:
        return "Use guardian allow file_delete --ttl 30 to pre-authorize, or confirm interactively."
    if intent == C.PRIVILEGE_ESCALATION:
        return "Review the command carefully. Use guardian allow privilege_escalation --ttl 30."
    if intent == C.PROCESS_KILL:
        return "Consider graceful termination (kill <pid>) before kill -9."
    if intent == C.SYSTEM_CONFIG:
        return "Back up your configuration first."
    return None
