"""Intent classifier — deterministic regex/token heuristic (V1)."""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Intent names
# ---------------------------------------------------------------------------
SAFE_ECHO = "safe_echo"
SHELL_RUN = "shell_run"
FILE_DELETE = "file_delete"
NETWORK_EXEC = "network_exec"
PRIVILEGE_ESCALATION = "privilege_escalation"
DISK_FORMAT = "disk_format"
PROCESS_KILL = "process_kill"
SYSTEM_CONFIG = "system_config"

ALL_INTENTS: list[str] = [
    SAFE_ECHO,
    SHELL_RUN,
    FILE_DELETE,
    NETWORK_EXEC,
    PRIVILEGE_ESCALATION,
    DISK_FORMAT,
    PROCESS_KILL,
    SYSTEM_CONFIG,
]

# ---------------------------------------------------------------------------
# Classification rules (order matters — first match wins)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Rule:
    intent: str
    pattern: re.Pattern[str]


_RULES: list[_Rule] = [
    # ---- disk_format (before generic) ----
    _Rule(DISK_FORMAT, re.compile(
        r"""(^|\||\;|\&\&)\s*(mkfs|format\s+\w+\:|diskpart|dd\s+)""", re.I | re.X)),
    _Rule(DISK_FORMAT, re.compile(
        r"""\bdd\b.*\bof=/dev/""", re.I)),

    # ---- network_exec (pipe-to-shell / powershell download-exec) ----
    _Rule(NETWORK_EXEC, re.compile(
        r"""(curl|wget)\s+.*\|\s*(ba)?sh""", re.I)),
    _Rule(NETWORK_EXEC, re.compile(
        r"""powershell\s+.*(\biex\b|\bInvoke-Expression\b|\biwr\b.*\|\s*iex)""", re.I)),
    _Rule(NETWORK_EXEC, re.compile(
        r"""(curl|wget|Invoke-WebRequest|iwr)\s+.*\|\s*(iex|Invoke-Expression|sh|bash)""", re.I)),

    # ---- file_delete ----
    _Rule(FILE_DELETE, re.compile(
        r"""(^|\||\;|\&\&)\s*rm\s+""", re.I)),
    _Rule(FILE_DELETE, re.compile(
        r"""(^|\||\;|\&\&)\s*(del|rmdir|Remove-Item)\s+""", re.I)),

    # ---- privilege_escalation ----
    _Rule(PRIVILEGE_ESCALATION, re.compile(
        r"""(^|\||\;|\&\&)\s*(sudo|doas|runas|pkexec)\s+""", re.I)),
    _Rule(PRIVILEGE_ESCALATION, re.compile(
        r"""\bchmod\s+.*\b777\b""", re.I)),
    _Rule(PRIVILEGE_ESCALATION, re.compile(
        r"""\bchmod\s+-R\s+""", re.I)),

    # ---- process_kill ----
    _Rule(PROCESS_KILL, re.compile(
        r"""(^|\||\;|\&\&)\s*(kill|killall|pkill)\s+""", re.I)),
    _Rule(PROCESS_KILL, re.compile(
        r"""(^|\||\;|\&\&)\s*taskkill\s+""", re.I)),

    # ---- system_config ----
    _Rule(SYSTEM_CONFIG, re.compile(
        r"""(^|\||\;|\&\&)\s*(sysctl|systemctl|launchctl|reg\s+(add|delete))\s+""", re.I)),
    _Rule(SYSTEM_CONFIG, re.compile(
        r"""\bregedit\b""", re.I)),

    # ---- safe_echo (must be near the end) ----
    _Rule(SAFE_ECHO, re.compile(
        r"""^\s*echo\s+""", re.I)),
    _Rule(SAFE_ECHO, re.compile(
        r"""^\s*printf\s+""", re.I)),
]


def classify(command: str) -> str:
    """Return the intent string for *command*.  Falls back to ``shell_run``."""
    cmd = command.strip()
    for rule in _RULES:
        if rule.pattern.search(cmd):
            return rule.intent
    return SHELL_RUN
