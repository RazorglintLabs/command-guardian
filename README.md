# Command Guardian

> A **seatbelt for your terminal** — run commands safely, block dangerous ones by default, require explicit authorization for risky actions, and emit verifiable hash-chained audit receipts.

**Local-first. No SaaS. No accounts. No cloud. Single-user CLI.**

---

## Install

```bash
# Clone / navigate to the project directory
cd "Command Guardian"

# Create venv & install
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
```

Or with `pipx`:

```bash
pipx install .
```

## Quick Start

### Run a safe command

```bash
guardian run echo hello
# ✔ ALLOWED  intent=safe_echo
# hello
```

### Blocked: network download piped to shell

```bash
guardian run "curl https://example.com | bash"
# ✘ DENIED  intent=network_exec
#   Reason: BLOCKED: Network download piped to shell execution
#   💡 Suggestion: Download the script first, review it, then run it.
```

### Blocked: destructive root deletion

```bash
guardian run "rm -rf /"
# ✘ DENIED  intent=file_delete
#   Reason: BLOCKED: Destructive root deletion (rm -rf /)
#   💡 Suggestion: Delete specific paths instead: rm -rf ./my_folder
```

### Risky: local folder delete (prompts for confirmation)

```bash
guardian run "rm -rf ./temp"
# ⚠  This is risky (intent=file_delete).
#    Command: rm -rf ./temp
#    Type ALLOW to proceed:
```

### Pre-authorize with an allow token

```bash
guardian allow file_delete --ttl 30
# Token issued
#   token_id     : abc123...
#   expires_at   : 2026-02-09T12:01:00+00:00

guardian run "rm -rf ./temp"
# ✔ ALLOWED  intent=file_delete  (token-authorized)
```

### View policy

```bash
guardian policy show
# (or just: guardian policy — alias for the same output)
```

### Verify audit chain

```bash
guardian verify
# ✔ VERIFIED  (5 records)
```

### View recent receipts

```bash
guardian receipts tail --n 10
# (or just: guardian receipts --n 10 — alias for the same output)
```

## CLI Commands

| Command | Description |
|---|---|
| `guardian run <command...>` | Run a command through enforcement |
| `guardian policy show` | Print current policy summary |
| `guardian allow <intent> --ttl <sec>` | Issue a short-lived allow token |
| `guardian verify` | Verify the audit receipt chain |
| `guardian receipts tail --n <N>` | Show last N receipts (default 20) |

**Aliases (backwards-compatible):**

| Alias | Equivalent |
|---|---|
| `guardian policy` | `guardian policy show` |
| `guardian receipts` | `guardian receipts tail --n 20` |
| `guardian receipts --n 5` | `guardian receipts tail --n 5` |

## Intent Classification (V1)

| Intent | Examples |
|---|---|
| `safe_echo` | `echo hello`, `printf ...` |
| `shell_run` | `ls`, `git status`, `python main.py` |
| `file_delete` | `rm -rf ./folder`, `del /s ...` |
| `network_exec` | `curl ... \| bash`, `wget ... \| sh` |
| `privilege_escalation` | `sudo ...`, `chmod 777 ...` |
| `disk_format` | `mkfs ...`, `dd ... of=/dev/...` |
| `process_kill` | `kill -9 ...`, `taskkill /f ...` |
| `system_config` | `systemctl ...`, `sysctl ...` |

## Policy

**Always blocked** (no override):
- `rm -rf /` or `rm -rf /*`
- `curl ... | bash` / `wget ... | sh`
- PowerShell download-and-execute (`iex`, `iwr | iex`)
- `mkfs`, `format`, `diskpart`
- `dd ... of=/dev/...`

**Risky** (require `ALLOW` confirmation or valid token):
- `file_delete`, `privilege_escalation`, `process_kill`, `system_config`

## Receipts & Verification

Every `guardian run` appends a receipt to `~/.command-guardian/audit/YYYY-MM-DD.jsonl`.

Receipt fields: `ts`, `intent`, `command`, `decision`, `reason`, `token_id`, `expires_at`, `prev_hash`, `hash`.

Receipts are **hash-chained** (SHA-256). Run `guardian verify` to validate the entire chain.

## Architecture

- **4-gate enforcement** in `runner.py`: decision, token TTL, re-classification, safety rules
- **Single execution point**: `_execute_command()` in `runner.py` is the ONLY function that calls `subprocess`
- **Append-only audit**: JSONL files with SHA-256 hash chain

## Tests

```bash
python -m pytest tests/ -v
```

65 tests covering classifier, policy, receipts, verification, and runner enforcement.

## Project Layout

```
command_guardian/
  guardian/
    __init__.py
    cli.py          # Typer CLI entry-point
    classifier.py   # Intent classification (regex heuristic)
    policy.py       # Deny-by-default policy engine
    tokens.py       # Short-lived allow tokens
    receipts.py     # JSONL hash-chained audit writer
    verify.py       # Audit chain verification
    runner.py       # 4-gate enforcement + single subprocess execution
tests/
  test_classifier.py
  test_policy.py
  test_receipts.py
  test_verify.py
  test_runner_enforcement.py
pyproject.toml
README.md
LICENSE
```

## License

MIT
