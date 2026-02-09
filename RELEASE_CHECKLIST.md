# Release Checklist

> No excuses gate — every item must pass before shipping.

**One command:** `.\release.ps1` from the repo root runs all gates automatically.

- [ ] `python -m pytest -q` → **65 passed**
- [ ] `guardian verify` → **VERIFIED**
- [ ] Zip sanity check → **CLEAN** (no venvs, caches, `.pyc`, build artifacts, OS junk)
- [ ] Fresh install from zip → CLI works + tests pass
  ```powershell
  # Windows validation sequence:
  $tmp = "$env:TEMP\cg-release-test"
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  mkdir $tmp; Add-Type -AssemblyName System.IO.Compression.FileSystem
  [IO.Compression.ZipFile]::ExtractToDirectory("$PWD\dist\Command-Guardian-release.zip", $tmp)
  python -m venv "$tmp\.venv"; & "$tmp\.venv\Scripts\Activate.ps1"
  Set-Location $tmp; pip install -e ".[dev]"
  guardian --help; guardian policy show; guardian receipts tail --n 5
  python -m pytest -q
  deactivate; Remove-Item -Recurse -Force $tmp
  ```
- [ ] Output artifacts in `dist/`:
  - `dist/Command-Guardian-release.zip`
  - `dist/CHECKSUMS.sha256`
