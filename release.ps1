#!/usr/bin/env pwsh
# release.ps1 — Build a clean, gate-enforced release zip for Command Guardian.
# Usage:  .\release.ps1 [-OutputName "Custom-Name.zip"] [-SkipTests]
#
# Gates (all must pass or the script aborts):
#   1. python -m pytest -q   → all tests green
#   2. guardian verify        → audit chain intact
#   3. Build zip into dist/   → excludes dev/build/OS artifacts
#   4. Scan zip for junk      → mirrors Gate 3 exclusion set exactly
#   5. Generate dist/CHECKSUMS.sha256

param(
    [string]$OutputName = "Command-Guardian-release.zip",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

# ── Robust script directory resolution ────────────────────────────────────

if ($PSScriptRoot -and (Test-Path $PSScriptRoot)) {
    $ScriptDir = $PSScriptRoot
} else {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
Set-Location $ScriptDir
Write-Host "Using script directory: $ScriptDir" -ForegroundColor DarkGray

# ── Shared exclusion pattern (single source of truth for Gate 3 & 4) ──────
# Categories:
#   virtualenv       .venv/ venv/ ENV/
#   caches           __pycache__/ .pytest_cache/ .mypy_cache/ .ruff_cache/
#   compiled python  *.pyc *.pyo
#   OS junk          .DS_Store Thumbs.db Desktop.ini
#   build artifacts  dist/ build/ *.egg-info/ htmlcov/ .coverage
#   staging          _release_test/
#   self             the zip and checksum themselves

$JunkPattern = '(^|[\\/])(\.venv|venv|ENV|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.egg-info|dist|build|htmlcov|\.coverage|_release_test)([\\/]|$)|\.pyc$|\.pyo$|\.DS_Store$|Thumbs\.db$|Desktop\.ini$|Command-Guardian-release\.zip$|CHECKSUMS\.sha256$'

# ── Helpers ───────────────────────────────────────────────────────────────

function Write-Gate([string]$label) { Write-Host "`n━━ GATE: $label ━━" -ForegroundColor Cyan }
function Write-Pass([string]$msg)   { Write-Host "  ✅ $msg" -ForegroundColor Green }
function Write-Fail([string]$msg)   { Write-Host "  ❌ $msg" -ForegroundColor Red; exit 1 }

# ── Gate 1: Tests ─────────────────────────────────────────────────────────

if (-not $SkipTests) {
    Write-Gate "Tests (python -m pytest -q)"
    $env:PYTHONIOENCODING = "utf-8"
    $testOutput = python -m pytest -q 2>&1 | Out-String
    $testExit = $LASTEXITCODE
    $env:PYTHONIOENCODING = $null
    if ($testExit -ne 0) {
        Write-Host $testOutput
        Write-Fail "Tests failed (exit code $testExit). Aborting release."
    }
    $passLine = ($testOutput -split "`n" | Where-Object { $_ -match '\d+ passed' } | Select-Object -Last 1).Trim()
    Write-Pass $passLine
} else {
    Write-Host "`n  ⏩ Tests skipped (--SkipTests)" -ForegroundColor Yellow
}

# ── Gate 2: Audit chain ──────────────────────────────────────────────────

Write-Gate "Audit chain (guardian verify)"
$env:PYTHONIOENCODING = "utf-8"
$verifyOutput = guardian verify 2>&1 | Out-String
$verifyExit = $LASTEXITCODE
$env:PYTHONIOENCODING = $null
if ($verifyExit -eq 0) {
    Write-Pass ($verifyOutput.Trim() -replace '\e\[[0-9;]*m', '')
} elseif ($verifyOutput -match "No receipts") {
    Write-Pass "No receipts yet (fresh machine) — acceptable."
} else {
    Write-Host $verifyOutput
    Write-Fail "Audit chain verification failed. Aborting release."
}

# ── Gate 3: Build zip into dist/ ─────────────────────────────────────────

Write-Gate "Build zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression

$distDir = Join-Path $ScriptDir "dist"
if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir | Out-Null }

$dst = Join-Path $distDir $OutputName
if (Test-Path $dst) { Remove-Item -Force $dst }

$zip = [System.IO.Compression.ZipFile]::Open($dst, [System.IO.Compression.ZipArchiveMode]::Create)

try {
    $files = Get-ChildItem -Path $ScriptDir -Recurse -File
    $count = 0
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($ScriptDir.Length + 1)
        if ($rel -notmatch $JunkPattern) {
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip, $f.FullName, $rel,
                [System.IO.Compression.CompressionLevel]::Optimal
            ) | Out-Null
            $count++
        }
    }
} finally {
    $zip.Dispose()
}

$size = (Get-Item $dst).Length
Write-Pass "Packed $count files -> $OutputName ($("{0:N0}" -f $size) bytes)"

# ── Gate 4: Scan zip for junk (mirrors Gate 3 exclusion set) ─────────────

Write-Gate "Scan zip for junk"
$zipCheck = [System.IO.Compression.ZipFile]::OpenRead($dst)

# Translate the same $JunkPattern into forward-slash form for zip entry names
$ZipJunkPattern = '(^|/)(\.venv|venv|ENV|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.egg-info|dist|build|htmlcov|\.coverage|_release_test)(/|$)|\.pyc$|\.pyo$|\.DS_Store$|Thumbs\.db$|Desktop\.ini$'

$bad = $zipCheck.Entries | Where-Object { $_.FullName -match $ZipJunkPattern }
$zipCheck.Dispose()

if ($bad) {
    $shown = $bad | Select-Object -First 10
    $shown | ForEach-Object { Write-Host "  JUNK: $($_.FullName)" -ForegroundColor Red }
    if ($bad.Count -gt 10) {
        Write-Host "  ... and $($bad.Count - 10) more." -ForegroundColor Red
    }
    Write-Fail "Zip contains $($bad.Count) excluded artifact(s). Aborting."
}
Write-Pass "CLEAN — no venvs, caches, compiled python, build artifacts, or OS junk."

# ── Gate 5: Generate dist/CHECKSUMS.sha256 ────────────────────────────────

Write-Gate "Generate CHECKSUMS.sha256"
$hash = (Get-FileHash -Path $dst -Algorithm SHA256).Hash.ToLower()
$checksumLine = "$hash  $OutputName"
$checksumFile = Join-Path $distDir "CHECKSUMS.sha256"
Set-Content -Path $checksumFile -Value $checksumLine -Encoding UTF8
Write-Pass $checksumLine

# ── Done ──────────────────────────────────────────────────────────────────

$hashShort = $hash.Substring(0, 12)
Write-Host "`n━━ RELEASE COMPLETE ━━" -ForegroundColor Green
Write-Host "  Zip      : $(Resolve-Path $dst)"
Write-Host "  Checksum : $(Resolve-Path $checksumFile)"
Write-Host "  Size     : $("{0:N0}" -f $size) bytes, $count files"
Write-Host "  SHA-256  : ${hashShort}..."
Write-Host ""
