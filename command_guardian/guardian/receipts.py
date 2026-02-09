"""Receipt writer — append-only JSONL with SHA-256 hash chain."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

AUDIT_DIR = Path.home() / ".command-guardian" / "audit"

GENESIS_HASH = "0" * 64  # prev_hash for the very first record in a day-file


def _ensure_dir() -> None:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)


def _today_file() -> Path:
    _ensure_dir()
    return AUDIT_DIR / f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.jsonl"


def _last_hash(filepath: Path) -> str:
    """Return the hash of the last record in *filepath*, or GENESIS_HASH."""
    if not filepath.exists():
        return GENESIS_HASH
    lines = filepath.read_text(encoding="utf-8").strip().splitlines()
    if not lines:
        return GENESIS_HASH
    last = json.loads(lines[-1])
    return last.get("hash", GENESIS_HASH)


def _canonical_json(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _compute_hash(record: dict) -> str:
    """Compute SHA-256 over canonical JSON of *record* (``hash`` key excluded)."""
    to_hash = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canonical_json(to_hash).encode("utf-8")).hexdigest()


def write_receipt(
    *,
    intent: str,
    command: str,
    decision: str,
    reason: str,
    token_id: Optional[str] = None,
    expires_at: Optional[str] = None,
) -> dict:
    """Append a receipt to today's audit JSONL file. Returns the record dict."""
    filepath = _today_file()
    prev = _last_hash(filepath)

    record: dict = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "intent": intent,
        "command": command,
        "decision": decision,
        "reason": reason,
        "token_id": token_id,
        "expires_at": expires_at,
        "prev_hash": prev,
    }
    record["hash"] = _compute_hash(record)

    with filepath.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")

    return record


def read_receipts(filepath: Path) -> list[dict]:
    """Read all receipt records from a JSONL file."""
    if not filepath.exists():
        return []
    lines = filepath.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def get_all_receipt_files() -> list[Path]:
    """Return all .jsonl files in the audit dir, sorted by name (date)."""
    _ensure_dir()
    return sorted(AUDIT_DIR.glob("*.jsonl"))


def tail_receipts(n: int = 20) -> list[dict]:
    """Return the last *n* receipts across all files."""
    files = get_all_receipt_files()
    all_records: list[dict] = []
    for f in reversed(files):
        records = read_receipts(f)
        all_records = records + all_records
        if len(all_records) >= n:
            break
    return all_records[-n:]
