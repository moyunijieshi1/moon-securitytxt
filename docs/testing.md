# Testing

## Overview

- **102 named tests** across 10 `test_*.mbt` files, one file per module
  plus property and truncation suites.
- **Deterministic property cases** (fixed grids, no randomness):
  date-time round-trips, calendar tables, offset grids, document
  round-trips, URI scheme grids, language tag grids.
- **Truncation-fuzz cases**: every prefix, sampled single-byte
  mutations and UTF-8 boundary grids of the base fixtures, plus sampled
  prefixes of a signed envelope. The contract is: every input returns
  `Ok` or a structured `Err` — the parser never crashes on untrusted
  input.
- RFC 9116 Appendix A.1 is reproduced verbatim as a conformance
  fixture (see THIRD_PARTY_NOTICES.md), including its known errata.

## Conventions

- Custom assertion helpers (`assert_true`, `assert_str_eq`, ...) fail
  loudly via `fail()`; helpers never silently pass.
- `unwrap_*` helpers fail the test with the underlying error message;
  `expect_*` helpers require an error and return it for inspection.
- All date-time tests pass `now` explicitly — nothing reads the clock.
- Truncation tests assert exact case counts, so a regression in loop
  bounds fails loudly.

## Running

```console
moon test --target wasm-gc
moon test --target js
moon test --target native
```

All three targets must be green; `scripts/verify_all.ps1` enforces
this plus `moon fmt --check`, CLI smoke tests and the examples.

## Coverage notes

The named tests cover: structured error rendering and bounds; every
resource limit; date-time parsing/formatting/arithmetic edge cases
(leap years, leap seconds, offsets, fractional digits, epoch anchors);
the field registry and URI/language checks; parser structure,
positions, encodings and syntax errors; the PGP envelope (detection,
dash-escaping, malformed envelopes); validator required fields,
cardinality and value constraints; retrieval contexts and multi-Canonical
matching; strict UTF-8 boundary cases; serializer
round-trips and builder order/validation; audit findings, severities
and thresholds.
