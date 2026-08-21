# Changelog

All notable changes to `moyunijieshi1/moon-securitytxt` are documented here.
The project follows semantic versioning.

## 0.1.0 — 2026-08-21

First stable release and OSC 2026 final-review submission.

### Added

- Byte-accurate, strictly validating RFC 9116 security.txt parser
  (comments, blank lines, CRLF, UTF-8 with BOM handling, line/byte
  positions for every field, resource limits).
- OpenPGP cleartext-signature envelope detection (RFC 4880 §7) with
  cleartext extraction and `SignedUnverified` signature state; no
  cryptographic verification is performed or claimed.
- Semantic validator enforcing RFC 9116 field constraints: required
  `Contact` and `Expires`, singleton cardinality, per-field value
  formats (URIs, HTTPS web URIs, RFC 3339 date-times, RFC 5646-shaped
  language tags). `validate` returns the first error; `validate_all`
  collects every error.
- Structured errors (`SecurityTxtError`) with stage, kind, line, column,
  byte offset and message; no error is a bare string.
- RFC 3339 date-time support for `Expires`: parsing (fractional seconds
  and numeric offsets), formatting, epoch
  arithmetic, expiry and freshness checks with an explicit `now`
  parameter (deterministic by design).
- Retrieval-context checks: HTTPS `/.well-known/security.txt` location,
  `text/plain; charset=utf-8` content type, multi-`Canonical` comparison.
  The library never fetches anything.
- Deterministic serializer and a validated generator
  (`SecurityTxtBuilder`); generated documents always pass the validator.
- Advisory audit layer (freshness, missing optional fields, canonical
  mismatch, duplicate singletons, unknown
  extensions, invalid context, unsigned document) kept strictly
  separate from validation.
- `securitytxt-tool` CLI: `parse`, `validate`, `fresh`, `generate`,
  `audit`, `stats`, `--version`, `--help`. Input via `--text` for target
  portability; no file or network access.
- Five runnable examples: `parse`, `validate`, `freshness`, `generate`,
  `audit`.
- Test suite: 102 named tests plus deterministic property grids and
  truncation-fuzz cases (every input returns `Ok` or a structured `Err`;
  the parser never crashes). Green on wasm-gc, js and native.
- Warning-free release gate, GitHub Actions verification and reproducible
  CLI/example/package checks.

### Deliberately out of scope

- No HTTP client, DNS, TLS, PGP key/signature verification, certificate
  validation or security scanning. The library must never be usable as a
  scanner, and a security.txt document grants no testing permission.
