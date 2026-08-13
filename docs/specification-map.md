# RFC 9116 Specification Map

| RFC 9116 | Requirement | Implementation and tests |
| --- | --- | --- |
| Section 2 | UTF-8 text, LF/CRLF, fields and blank lines | `parser.mbt`; parser, UTF-8, truncation tests |
| Section 2.1 | Comments beginning with `#` | Parser stores comments; serializer re-emits them |
| Section 2.3 | Optional OpenPGP cleartext signature | `signed.mbt`; signed-envelope tests; always unverified |
| Section 2.4 | Unknown registered fields ignored | `Extension`; parser and audit tests |
| Section 2.5.1 | `Acknowledgments` URI; HTTPS for web | `field.mbt`; field/validator tests |
| Section 2.5.2 | Repeatable `Canonical`; HTTPS for web | `canonicals()`; context matching against any listed URI |
| Section 2.5.3 | One or more ordered `Contact` values | `contacts()`, `preferred_contact()`; ordering tests |
| Section 2.5.4 | `Encryption` URI; HTTPS for web | Supports RFC examples `https:`, `dns:`, `openpgp4fpr:` |
| Section 2.5.5 | Exactly one RFC 3339 `Expires` | `datetime.mbt`, `validator.mbt`; date/cardinality tests |
| Sections 2.5.6-2.5.7 | `Hiring` and `Policy` URIs | Field and validator tests |
| Section 2.5.8 | At most one language-tag list | Project-defined RFC 5646-shaped subset; language tests |
| Section 3 | HTTPS well-known location and text/plain UTF-8 | `context.mbt`; caller-supplied context tests |
| Section 4 | ABNF line shape and first-colon split | Parser tests, including URI colons and required SP |
| Section 5.4 | Defensive input limits | `limits.mbt`; every limit has tests |
| Section 5.5 | No implied testing permission | `docs/security.md`, README, limitations |
| Appendix A.1 | Unsigned example | Standards fixture; see `THIRD_PARTY_NOTICES.md` |

## Intentional scope boundaries

- Lower-case `t` and `z` are accepted as RFC 3339 permits. Date-only and
  space-separated values are rejected because RFC 9116 imports `date-time`.
- URI validation is deliberately minimal and never performs network access.
- Language tags use a documented syntax subset rather than a registry-backed
  complete RFC 5646 implementation.
- OpenPGP signatures are detected and extracted but never verified.
