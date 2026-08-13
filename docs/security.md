# Security Design

## Hard exclusions

This library deliberately does **not** implement, and its API cannot be
extended to perform:

- HTTP clients or any network I/O — documents are parsed from strings
  or bytes supplied by the caller;
- DNS resolution;
- TLS connections or certificate validation;
- OpenPGP key management, signature or message verification;
- security scanning of any kind.

The library cannot become a scanner: it has no transport, no
concurrency and no I/O beyond printing.

## Security.txt does not grant permission

A `security.txt` file tells researchers *how* a vendor wants to be
contacted. It grants **no** authorization for testing. Nothing in this
library — not `validate`, not `audit`, not the CLI — should be
interpreted as permission or as evidence of authorization. See RFC
9116 §8 (Security Considerations).

## Signature state semantics

A document that carries an OpenPGP cleartext-signature envelope is
reported as `SignedUnverified`. The parser extracts the cleartext and
records armor headers, but performs no cryptographic check, and the
state can never become `verified` through this library. Downstream
code must not treat `SignedUnverified` as an authenticity guarantee.

## Consumer checklist

Before acting on a parsed document, consumers should validate it, check
freshness with a trusted `now`, compare every declared Canonical location with
the actual retrieval URI, and independently establish trust in contacts and
keys. Validation reports syntax and RFC constraints; it does not establish
ownership, authorization, availability, or cryptographic authenticity.

## Parser hardening

- Strict UTF-8 validation (rejects overlong encodings, surrogates,
  invalid sequences) with exact byte offsets.
- Resource limits on input size, line count, line length, field count
  and field value length (`Limits::strict()`, `default()`,
  `permissive()`, `custom(...)`).
- The truncation-fuzz suite guarantees: every truncated, mutated or
  malformed input returns `Ok` or a structured `Err`; the parser never
  panics on attacker-controlled input.
- Control characters in field values are rejected before they can
  reach downstream consumers.

## Determinism

Nothing reads the wall clock; all freshness functions take `now`
explicitly. This removes a whole class of flaky, environment-dependent
behavior and makes audits reproducible.
