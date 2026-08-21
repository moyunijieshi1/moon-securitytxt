# Reproducing Verification

The project requires a local MoonBit toolchain and Python 3. It has no runtime
dependency beyond the MoonBit standard library and performs no network access.

From the project root, run:

```powershell
$env:MOON_BIN = "D:\Moonbit\bin\moon.exe"
$env:MOON_TARGET_DIR = "D:\Moonbit\.moon-securitytxt-build"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_all.ps1
```

`MOON_BIN` may point to any compatible `moon` executable. `MOON_TARGET_DIR` is
optional; the script otherwise uses a sibling build directory so stale or
permission-restricted in-tree build artifacts cannot invalidate verification.

The script checks formatting; compiles and runs warning-free tests on wasm-gc,
JavaScript, and native targets; runs CLI smoke tests and all examples; measures code and
test counts; and lists the package contents. Every external process exit code
is checked. Success ends with exactly:

```text
All verification steps passed.
```

No Git, login, publishing, HTTP, DNS, TLS, or signature-verification operation
is part of reproduction.

## Focused checks

During development, individual targets can be checked without running the full
gate:

```powershell
moon fmt --check
moon check --target wasm-gc --deny-warn
moon test --target wasm-gc --deny-warn
```

Run `verify_all.ps1` before release or publication because only the full gate
covers JavaScript, native, CLI smoke tests, examples, metrics, and packaging.
