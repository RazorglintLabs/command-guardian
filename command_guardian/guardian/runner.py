"""Runner — the ONLY place subprocess execution happens.

Implements 4-gate enforcement:
  1. decision == ALLOW
  2. token TTL not expired (if token-based)
  3. command still matches the classified intent & isn't reclassified into a blocked pattern
  4. command passes safety rules for that intent
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from . import classifier, policy, receipts, tokens


class ExecutionBlocked(Exception):
    """Raised when any enforcement gate fails."""


@dataclass
class RunResult:
    decision: str
    intent: str
    reason: str
    exit_code: int
    output: str | None = None
    receipt: dict | None = None


# ── The ONLY function that calls subprocess ──────────────────────────────

def _execute_command(command: str) -> tuple[int, str]:
    """Execute *command* in a shell subprocess. Returns (exit_code, combined_output)."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        output = result.stdout
        if result.stderr:
            output += result.stderr
        return result.returncode, output
    except subprocess.TimeoutExpired:
        return 124, "[guardian] Command timed out after 300s."
    except Exception as exc:
        return 1, f"[guardian] Execution error: {exc}"


# ── 4-gate enforcement ───────────────────────────────────────────────────

def run(
    command: str,
    *,
    skip_confirm: bool = False,
    confirm_callback: Optional[callable] = None,
) -> RunResult:
    """Run *command* through full 4-gate enforcement.

    Parameters
    ----------
    skip_confirm:
        If ``True``, never prompt (used by tests).
    confirm_callback:
        Optional callable that returns ``True`` to authorize a risky command.
        If ``None`` and a risky command needs confirmation, uses stdin prompt.
    """
    # ── Step 1: classify ──
    intent = classifier.classify(command)

    # ── Step 2: evaluate policy ──
    pol = policy.evaluate(command, intent)

    token_id: str | None = None
    expires_at: str | None = None

    # ── GATE 1 & 2: decision + token handling ──
    if pol.decision == policy.Decision.DENY and not pol.requires_auth:
        # Always-block
        rec = receipts.write_receipt(
            intent=intent,
            command=command,
            decision="DENY",
            reason=pol.reason,
        )
        return RunResult(
            decision="DENY",
            intent=intent,
            reason=pol.reason,
            exit_code=1,
            receipt=rec,
        )

    if pol.requires_auth:
        # Check for valid token first
        tok = tokens.find_valid_token(intent)
        if tok:
            token_id = tok["token_id"]
            expires_at = tok["expires_at"]
            # Token found — authorized
        elif skip_confirm:
            # No token, no interactive prompt → deny
            rec = receipts.write_receipt(
                intent=intent,
                command=command,
                decision="DENY",
                reason="Risky intent denied (no valid token, no interactive confirmation).",
            )
            return RunResult(
                decision="DENY",
                intent=intent,
                reason="Risky intent denied (no valid token, no interactive confirmation).",
                exit_code=1,
                receipt=rec,
            )
        else:
            # Interactive confirmation
            authorized = False
            if confirm_callback:
                authorized = confirm_callback(intent, command)
            else:
                authorized = _interactive_confirm(intent, command)

            if not authorized:
                rec = receipts.write_receipt(
                    intent=intent,
                    command=command,
                    decision="DENY",
                    reason="User declined interactive authorization.",
                )
                return RunResult(
                    decision="DENY",
                    intent=intent,
                    reason="User declined interactive authorization.",
                    exit_code=1,
                    receipt=rec,
                )

    # ── GATE 3: re-classify to catch manipulation ──
    re_intent = classifier.classify(command)
    re_pol = policy.evaluate(command, re_intent)
    if re_pol.decision == policy.Decision.DENY and not re_pol.requires_auth:
        reason = f"Re-classification blocked: {re_pol.reason}"
        rec = receipts.write_receipt(
            intent=re_intent,
            command=command,
            decision="DENY",
            reason=reason,
        )
        raise ExecutionBlocked(reason)

    # ── GATE 4: safety rules passed (policy didn't block) ──
    # All gates passed — execute
    rec = receipts.write_receipt(
        intent=intent,
        command=command,
        decision="ALLOW",
        reason=pol.reason if pol.decision == policy.Decision.ALLOW else "Authorized (token or interactive).",
        token_id=token_id,
        expires_at=expires_at,
    )

    exit_code, output = _execute_command(command)

    return RunResult(
        decision="ALLOW",
        intent=intent,
        reason="Executed successfully." if exit_code == 0 else f"Command exited with code {exit_code}.",
        exit_code=exit_code,
        output=output,
        receipt=rec,
    )


def _interactive_confirm(intent: str, command: str) -> bool:
    """Prompt on stdin. Returns True if user types ALLOW."""
    print(f"\n⚠  This is risky (intent={intent}).")
    print(f"   Command: {command}")
    try:
        answer = input("   Type ALLOW to proceed: ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "ALLOW"
