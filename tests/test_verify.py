"""Tests for audit chain verification."""

import json
from unittest.mock import patch

import pytest

from guardian import receipts as R
from guardian.verify import verify_chain


@pytest.fixture(autouse=True)
def _tmp_audit_dir(tmp_path):
    with patch.object(R, "AUDIT_DIR", tmp_path / "audit"):
        yield


def _write(**kw):
    defaults = dict(intent="safe_echo", command="echo hi", decision="ALLOW", reason="ok")
    defaults.update(kw)
    return R.write_receipt(**defaults)


class TestVerify:
    def test_empty_chain(self):
        result = verify_chain()
        assert result.ok
        assert result.total == 0

    def test_valid_chain(self):
        for i in range(10):
            _write(command=f"echo {i}")
        result = verify_chain()
        assert result.ok
        assert result.total == 10

    def test_tampered_hash(self):
        _write(command="echo one")
        _write(command="echo two")

        filepath = list(R.AUDIT_DIR.glob("*.jsonl"))[0]
        lines = filepath.read_text(encoding="utf-8").strip().splitlines()
        record = json.loads(lines[0])
        record["hash"] = "deadbeef" * 8
        lines[0] = json.dumps(record, separators=(",", ":"))
        filepath.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_chain()
        assert not result.ok
        assert result.failed_index == 0

    def test_tampered_prev_hash(self):
        _write(command="echo one")
        _write(command="echo two")
        _write(command="echo three")

        filepath = list(R.AUDIT_DIR.glob("*.jsonl"))[0]
        lines = filepath.read_text(encoding="utf-8").strip().splitlines()
        record = json.loads(lines[1])
        record["prev_hash"] = "badc0ffee" + "0" * 55
        lines[1] = json.dumps(record, separators=(",", ":"))
        filepath.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_chain()
        assert not result.ok
        assert result.failed_index == 1
