"""Allow-token store — short-lived local tokens stored in JSON."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

CONFIG_DIR = Path.home() / ".command-guardian"
TOKENS_FILE = CONFIG_DIR / "tokens.json"

DEFAULT_TTL = 60  # seconds


def _ensure_store() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not TOKENS_FILE.exists():
        TOKENS_FILE.write_text("[]", encoding="utf-8")
    return TOKENS_FILE


def _load_tokens() -> list[dict]:
    _ensure_store()
    return json.loads(TOKENS_FILE.read_text(encoding="utf-8"))


def _save_tokens(tokens: list[dict]) -> None:
    _ensure_store()
    TOKENS_FILE.write_text(json.dumps(tokens, indent=2), encoding="utf-8")


def _canonical_hash(record: dict) -> str:
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def issue_token(intent: str, ttl: int = DEFAULT_TTL) -> dict:
    """Create a new allow token for *intent* with given *ttl* (seconds)."""
    now = datetime.now(timezone.utc)
    token_id = uuid.uuid4().hex[:16]
    expires_at = (now + timedelta(seconds=ttl)).isoformat()
    record = {
        "token_id": token_id,
        "intent": intent,
        "issued_at": now.isoformat(),
        "expires_at": expires_at,
        "ttl": ttl,
    }
    record["decision_hash"] = _canonical_hash(record)

    tokens = _load_tokens()
    tokens.append(record)
    _save_tokens(tokens)
    return record


def find_valid_token(intent: str) -> Optional[dict]:
    """Return the first unexpired token for *intent*, or ``None``."""
    now = datetime.now(timezone.utc)
    tokens = _load_tokens()
    for tok in tokens:
        if tok["intent"] != intent:
            continue
        exp = datetime.fromisoformat(tok["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp > now:
            return tok
    return None


def prune_expired() -> int:
    """Remove expired tokens. Returns count removed."""
    now = datetime.now(timezone.utc)
    tokens = _load_tokens()
    kept = []
    removed = 0
    for tok in tokens:
        exp = datetime.fromisoformat(tok["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp > now:
            kept.append(tok)
        else:
            removed += 1
    _save_tokens(kept)
    return removed
