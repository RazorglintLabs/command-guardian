"""Audit chain verification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import receipts as R


@dataclass
class VerifyResult:
    ok: bool
    total: int
    failed_index: Optional[int] = None
    failed_reason: Optional[str] = None


def verify_chain() -> VerifyResult:
    """Replay every receipt file and verify the hash chain.

    Returns a ``VerifyResult`` indicating success or the first failure.
    """
    files = R.get_all_receipt_files()
    global_index = 0
    prev_hash = R.GENESIS_HASH  # chain resets per day-file

    for filepath in files:
        records = R.read_receipts(filepath)
        # Reset chain at start of each day-file
        day_prev = R.GENESIS_HASH
        for i, record in enumerate(records):
            idx = global_index + i

            # Check prev_hash linkage
            expected_prev = day_prev
            if record.get("prev_hash") != expected_prev:
                return VerifyResult(
                    ok=False,
                    total=idx,
                    failed_index=idx,
                    failed_reason=(
                        f"prev_hash mismatch at record {idx}: "
                        f"expected {expected_prev[:16]}…, got {record.get('prev_hash', 'MISSING')[:16]}…"
                    ),
                )

            # Recompute hash
            recomputed = R._compute_hash(record)
            if record.get("hash") != recomputed:
                return VerifyResult(
                    ok=False,
                    total=idx,
                    failed_index=idx,
                    failed_reason=(
                        f"hash mismatch at record {idx}: "
                        f"expected {recomputed[:16]}…, got {record.get('hash', 'MISSING')[:16]}…"
                    ),
                )

            day_prev = record["hash"]

        global_index += len(records)

    return VerifyResult(ok=True, total=global_index)
