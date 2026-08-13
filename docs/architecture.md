# Architecture

## Layering

The library is split into three strictly separated layers:

| Layer | Modules | Owns |
| --- | --- | --- |
| Syntax | `parser.mbt`, `signed.mbt`, `limits.mbt`, `error.mbt` | Byte-level decoding, line splitting, field splitting, the PGP envelope, resource caps, structured errors |
| Semantics | `field.mbt`, `datetime.mbt`, `validator.mbt`, `context.mbt`, `model.mbt` | Field registry, RFC 3339 dates, RFC 9116 constraints (required fields, cardinality, value formats), retrieval-context checks |
| Tooling | `serializer.mbt`, `audit.mbt` | Deterministic rendering, validated generation, advisory findings |

Rules that keep the layers apart:

- The parser never decides whether a document is "valid" — it only
  reports structure and syntax. A document with two `Expires` fields
  parses fine; the validator rejects it.
- The validator never reports recommendations — `Policy` missing is
  legal RFC 9116; only the audit layer flags it (as `Info`).
- The audit layer never fails a document; it returns findings with
  severities.
- Errors are always `SecurityTxtError` values (stage + kind + line +
  column + byte offset + message), never bare strings.

## Data flow

```
text ──▶ parse_security_txt ──▶ SecurityTxt ──▶ validate ──▶ Result[Unit, Error]
                                   │                    └─▶ validate_all ──▶ Array[Error]
                                   ├──▶ serialize_security_txt ──▶ text
                                   ├──▶ audit(now, context) ──▶ Array[AuditFinding]
                                   └──▶ SecurityTxtBuilder.build ──▶ validated document
```

`parse_security_txt_bytes` takes raw `Bytes` and performs strict UTF-8
decoding with exact byte offsets; `parse_security_txt` is the `String`
convenience wrapper. Both take resource limits.

## Positions

Every field entry records its source line and byte offset; every error
records line, column and byte offset. Multi-byte UTF-8 sequences never
confuse offsets because the parser works at byte level and the decoder
validates each sequence.

## Signature handling

`signed.mbt` detects RFC 4880 §7 cleartext-signature envelopes (armor
header lines, cleartext body, signature block), reverses dash-escaping
and extracts the cleartext. The parsed document records
`SignedUnverified` plus armor headers. There is deliberately no
`SignedVerified` state: cryptographic verification is out of scope and
can never be implied.

## Determinism

- All date-time functions take `now` explicitly; nothing reads the
  clock.
- The serializer emits a fixed, documented order.
- The builder assembles fields in a fixed order and validates before
  returning.
- Property and truncation tests are generated deterministically (fixed
  grids, no randomness).
