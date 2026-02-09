"""Tests for receipt writer and hash chain."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from guardian import receipts as R


@pytest.fixture(autouse=True)
def _tmp_audit_dir(tmp_path):
    """Redirect AUDIT_DIR to a temp directory for every test."""
    with patch.object(R, "AUDIT_DIR", tmp_path / "audit"):
        yield


def _write(intent="safe_echo", command="echo hi", decision="ALLOW", reason="ok"):
    return R.write_receipt(intent=intent, command=command, decision=decision, reason=reason)


class TestWriteReceipt:
    def test_creates_file(self):
        rec = _write()
        files = list(R.AUDIT_DIR.glob("*.jsonl"))
        assert len(files) == 1
        assert rec["hash"]
        assert rec["prev_hash"] == R.GENESIS_HASH

    def test_chain_links(self):
        r1 = _write(command="echo one")
        r2 = _write(command="echo two")
        assert r2["prev_hash"] == r1["hash"]

    def test_hash_deterministic(self):
        rec = _write()
        recomputed = R._compute_hash(rec)
        assert rec["hash"] == recomputed

    def test_tamper_detection(self):
        r1 = _write(command="echo one")
        r2 = _write(command="echo two")

        # Tamper with r1 in the file
        filepath = list(R.AUDIT_DIR.glob("*.jsonl"))[0]
        lines = filepath.read_text(encoding="utf-8").strip().splitlines()
        record = json.loads(lines[0])
        record["command"] = "echo HACKED"
        lines[0] = json.dumps(record, separators=(",", ":"))
        filepath.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Recompute should fail
        tampered = json.loads(filepath.read_text(encoding="utf-8").strip().splitlines()[0])
        recomputed = R._compute_hash(tampered)
        assert tampered["hash"] != recomputed


class TestTailReceipts:
    def test_tail(self):
        for i in range(5):
            _write(command=f"echo {i}")
        recs = R.tail_receipts(3)
        assert len(recs) == 3
        assert recs[-1]["command"] == "echo 4"
