# API Guide

## Parsing

```moonbit
parse_security_txt(input : String) -> Result[SecurityTxt, SecurityTxtError]
parse_security_txt_with_limits(input : String, limits : Limits) -> Result[SecurityTxt, SecurityTxtError]
parse_security_txt_bytes(input : Bytes, limits : Limits) -> Result[SecurityTxt, SecurityTxtError]
```

The `Bytes` entry point is the strict one: it validates UTF-8 itself so
every error carries an exact byte offset. `parse_security_txt` is the
convenience wrapper with default limits.

`SecurityTxt` accessors: `fields()`, `entries()` (with positions),
`contacts()`, `preferred_contact()` (first `Contact`, in document
order — no scheme ranking is invented), `expires_value()`, `expires()`,
`canonical()`, `canonicals()`, `encryption()`, `acknowledgments()`, `policy()`,
`hiring()`, `preferred_languages()`, `extensions()`, `comments()`,
`is_signed()`, `signature_state()`, `armor_headers()`, `line_count()`,
`byte_count()`, `field_count()`, `standard_field_count()`,
`extension_field_count()`.

Field values are stored with the `Name: ` separator and surrounding
WSP stripped — the syntax, not the value.

## Validation

```moonbit
validate(document) -> Result[Unit, SecurityTxtError]
validate_all(document) -> Array[SecurityTxtError]
```

`validate` returns the first error; `validate_all` collects every error
in deterministic order (per-field value errors in document order, then
required fields, then cardinality).

## Ordering guarantees

The parser preserves source field order. `contacts()` and `canonicals()` return
values in that same order, and `preferred_contact()` returns the first Contact
without inventing a URI-scheme preference. Serialization retains entry order;
the builder uses its documented fixed order for deterministic generation.

## Freshness

```moonbit
parse_rfc3339(value) -> Result[DateTime, SecurityTxtError]
make_utc(y, mo, d, h, mi, s) -> Result[DateTime, SecurityTxtError]
is_expired(expires, now) -> Bool
time_until_expiry(expires, now) -> Int64
EXPIRES_SOON_SECONDS // 30 days (project-defined advisory threshold)
```

`now` is always an explicit parameter — deterministic by design.

## Retrieval context

```moonbit
security_txt_context(retrieval_uri, content_type) -> SecurityTxtContext
validate_context(context) -> Result[Unit, SecurityTxtError]
validate_retrieval_context(document, context) -> Result[Unit, SecurityTxtError]
```

`validate_context` checks the HTTPS `/.well-known/security.txt`
location and `text/plain; charset=utf-8`; `validate_retrieval_context`
compares the retrieval URI against all `Canonical` values (exact string
equality; at least one listed value must match).
Both only inspect caller-supplied strings; nothing is fetched.

## Generation

```moonbit
new_builder()
  .contact(uri)            // repeatable, order kept
  .expires(dt)
  .canonical(uri)
  .encryption(uri)
  .acknowledgments(uri)    // repeatable
  .policy(uri)
  .hiring(uri)
  .preferred_languages(tags)
  .extension(name, value)  // repeatable
  .comment(text)           // repeatable; text follows the '#' verbatim
  .build() -> Result[SecurityTxt, SecurityTxtError]
```

`build` assembles fields in a fixed order and runs the validator, so it
returns either a valid document or the first validation error.

## Audit

```moonbit
audit(document, now, context) -> Array[AuditFinding]
```

Findings carry `kind()` (11 kinds), `severity()` (`Info`/`Warning`),
`message()` and `line()` (0 for document-wide findings). Findings are
advisory — they never make a document invalid.

## Errors

Every error is a `SecurityTxtError` with `stage()`, `kind()`, `line()`,
`column()`, `byte_offset()` and `message()`; `to_string()` renders
`Stage::Kind at byte N, line L, column C: message`.
