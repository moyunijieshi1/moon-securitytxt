# moon-securitytxt

```text
Module: moyunijieshi1/moon-securitytxt
Version: 0.1.0
Status: final release
Repository: https://github.com/moyunijieshi1/moon-securitytxt
Mooncakes: published as moyunijieshi1/moon-securitytxt@0.1.0
Maintainer: 谭海杰 (@moyunijieshi1)
```

A pure-MoonBit RFC 9116 `security.txt` toolkit: parser, validator,
generator, freshness and audit. GitHub development package
`moyunijieshi1/moon-securitytxt`, version `0.1.0`.

## What it does

- **Parse** security.txt documents byte-accurately: comments, blank
  lines, CRLF, UTF-8 (with BOM), all eight standard RFC 9116 fields plus
  extension fields, and OpenPGP cleartext-signature envelopes — with
  line/column/byte positions for every field and every error.
- **Validate** against RFC 9116 constraints: required `Contact` and
  `Expires`, singleton cardinality, URI formats, HTTPS for web URIs,
  RFC 3339 date-times and language tags.
  `validate` returns the first error; `validate_all` collects all.
- **Check freshness** with an explicit `now` timestamp: expiry,
  seconds-until-expiry and the 30-day "expires soon" window.
- **Generate** valid documents with a builder that runs the validator
  before returning.
- **Audit** for advisory findings (expired/expiring documents, missing
  optional fields, canonical mismatches, duplicate singletons, unknown
  extensions and unsigned documents).
- **CLI** (`securitytxt-tool`) with `parse`, `validate`, `fresh`,
  `generate`, `audit` and `stats` commands, plus `--version`/`--help`.

## Field overview

| Field | Cardinality | Purpose |
| --- | --- | --- |
| `Contact` | One or more | Ordered reporting channels; the first is preferred |
| `Expires` | Exactly one | Time after which the document is stale |
| `Preferred-Languages` | Zero or one | Equally preferred report languages |
| Other standard fields | Optional, repeatable | Policy, keys, acknowledgments, hiring and canonical locations |
| Extension fields | Optional, repeatable | Forward-compatible registered or private information |

## What it does not do (by design)

- No HTTP client, DNS, TLS, PGP signature/key verification, certificate
  validation, file access or security scanning. The library never
  fetches anything and can never be assembled into a scanner.
- Signature handling stops at envelope detection: documents are reported
  as `SignedUnverified`, never `verified`.
- A `security.txt` document grants **no** permission for security
  testing. See docs/security.md.

## Quick start

```moonbit
let text =
  "Contact: mailto:security@example.com\n" +
  "Expires: 2027-01-01T00:00:00Z\n" +
  "Preferred-Languages: en, de\n"

match parse_security_txt(text) {
  Ok(doc) =>
    match validate(doc) {
      Ok(_) => println("valid; preferred contact: \{doc.preferred_contact().unwrap()}")
      Err(err) => println("invalid: \{err.to_string()}")
    }
  Err(err) => println("parse error: \{err.to_string()}")
}
```

CLI (input via `--text`; the tool never opens files):

```console
moon run ./cmd/securitytxt-tool --target wasm-gc -- validate --text "Contact: mailto:a@example.com`nExpires: 2027-01-01T00:00:00Z`n"
moon run ./cmd/securitytxt-tool --target wasm-gc -- fresh --text "..." --now 2026-08-13T00:00:00Z
```

## Project layout

| Path | Contents |
| --- | --- |
| `*.mbt` | Core library (parser, validator, serializer, audit, ...) |
| `test_*.mbt` | Named tests, property grids and truncation-fuzz suite |
| `cmd/securitytxt-tool/` | CLI executable package |
| `examples/` | Runnable examples (parse, validate, freshness, generate, audit) |
| `docs/` | Architecture, API, testing, security, limitations, CLI |
| `scripts/` | `verify_all.ps1`, `count_code.py` |

## Verification

```console
powershell -File scripts/verify_all.ps1
```

Runs `moon clean`, `moon fmt --check`, warning-free check+test on wasm-gc, js and
native, CLI smoke tests, all examples, code metrics and
`moon package --list`, ending with `All verification steps passed.`

## Tests

102 named tests plus deterministic property and truncation cases (see
docs/testing.md). All inputs — truncated, mutated or malformed — return
`Ok` or a structured `Err`; the parser never crashes.

## License

Apache-2.0. See LICENSE and THIRD_PARTY_NOTICES.md (the RFC 9116
Appendix A.1 example is reproduced as a test fixture).

## Project status

Maintained by 谭海杰 (`moyunijieshi1`) at
https://github.com/moyunijieshi1/moon-securitytxt. Version `0.1.0` is
published on Mooncakes:

```console
moon add moyunijieshi1/moon-securitytxt@0.1.0
```
