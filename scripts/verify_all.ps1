$ErrorActionPreference = "Stop"

function Resolve-Moon {
  if ($env:MOON_BIN -and (Test-Path $env:MOON_BIN)) {
    return $env:MOON_BIN
  }
  $cmd = Get-Command moon -ErrorAction SilentlyContinue
  if ($cmd) {
    return $cmd.Source
  }
  $fallback = "D:\Moonbit\bin\moon.exe"
  if (Test-Path $fallback) {
    return $fallback
  }
  throw "moon executable not found"
}

$Moon = Resolve-Moon
$Root = Split-Path -Parent $PSScriptRoot
$TargetDir = if ($env:MOON_TARGET_DIR) {
  $env:MOON_TARGET_DIR
} else {
  Join-Path (Split-Path -Parent $Root) ".moon-securitytxt-build"
}
Set-Location $Root

function Invoke-Checked {
  param(
    [Parameter(Mandatory = $true)][string]$Program,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
  )
  & $Program @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "command failed with exit code $LASTEXITCODE`: $Program $($Arguments -join ' ')"
  }
}

Invoke-Checked $Moon clean --target-dir $TargetDir
Invoke-Checked $Moon fmt --check --target-dir $TargetDir

Invoke-Checked $Moon check --target wasm-gc --deny-warn --target-dir $TargetDir
Invoke-Checked $Moon test --target wasm-gc --deny-warn --target-dir $TargetDir

Invoke-Checked $Moon check --target js --deny-warn --target-dir $TargetDir
Invoke-Checked $Moon test --target js --deny-warn --target-dir $TargetDir

Invoke-Checked $Moon check --target native --deny-warn --target-dir $TargetDir
Invoke-Checked $Moon test --target native --deny-warn --target-dir $TargetDir

# CLI smoke tests (input via --text; the CLI never opens files).
Invoke-Checked $Moon run ./cmd/securitytxt-tool --target wasm-gc --target-dir $TargetDir -- version
Invoke-Checked $Moon run ./cmd/securitytxt-tool --target wasm-gc --target-dir $TargetDir -- parse --text "Contact: mailto:a@example.com`nExpires: 2027-01-01T00:00:00Z`n"
Invoke-Checked $Moon run ./cmd/securitytxt-tool --target wasm-gc --target-dir $TargetDir -- validate --text "Contact: mailto:a@example.com`nExpires: 2027-01-01T00:00:00Z`n"
Invoke-Checked $Moon run ./cmd/securitytxt-tool --target wasm-gc --target-dir $TargetDir -- fresh --text "Contact: mailto:a@example.com`nExpires: 2027-01-01T00:00:00Z`n" --now 2026-08-13T00:00:00Z
Invoke-Checked $Moon run ./cmd/securitytxt-tool --target wasm-gc --target-dir $TargetDir -- generate --contact "mailto:a@example.com" --expires 2027-01-01T00:00:00Z --policy "https://example.com/policy"
Invoke-Checked $Moon run ./cmd/securitytxt-tool --target wasm-gc --target-dir $TargetDir -- audit --text "Contact: mailto:a@example.com`nExpires: 2027-01-01T00:00:00Z`n" --now 2026-08-13T00:00:00Z
Invoke-Checked $Moon run ./cmd/securitytxt-tool --target wasm-gc --target-dir $TargetDir -- stats --text "Contact: mailto:a@example.com`nExpires: 2027-01-01T00:00:00Z`n"

# Examples.
Invoke-Checked $Moon run ./examples/parse --target wasm-gc --target-dir $TargetDir
Invoke-Checked $Moon run ./examples/validate --target wasm-gc --target-dir $TargetDir
Invoke-Checked $Moon run ./examples/freshness --target wasm-gc --target-dir $TargetDir
Invoke-Checked $Moon run ./examples/generate --target wasm-gc --target-dir $TargetDir
Invoke-Checked $Moon run ./examples/audit --target wasm-gc --target-dir $TargetDir

Invoke-Checked python .\scripts\count_code.py
Invoke-Checked $Moon package --list --target-dir $TargetDir

Write-Output "All verification steps passed."
