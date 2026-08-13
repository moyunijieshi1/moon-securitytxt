# Known Limitations

## No file or network access

The library and CLI accept document text via strings or bytes. Reading files,
fetching URLs, redirect handling, DNS, TLS, and certificate validation are out
of scope; callers integrate their own transport.

## Date-time scope

- `parse_rfc3339` accepts the RFC 3339 `date-time` production used by RFC 9116,
  including `T`/`t`, fractional seconds (up to 9 digits), and `Z`/`z`/numeric
  offsets. Date-only and space-separated values are rejected.
- No timezone database or DST handling is included.
- Leap seconds are accepted and preserved; epoch arithmetic treats a leap
  second as equal to the following second.

## Language tags

`Preferred-Languages` uses a documented RFC 5646-shaped syntax subset. It does
not perform registry lookup and does not model grandfathered, irregular, or
extlang tags.

## URIs

URI checking validates scheme presence, rejects spaces and control characters,
and enforces HTTPS when a standard field contains a web URI. It is not a full
RFC 3986 parser: percent encoding, hosts, and network reachability are not
validated.

## Signatures

Only OpenPGP cleartext-signature envelopes are recognized. Cleartext is
extracted and marked `SignedUnverified`; no cryptographic verification is
performed. The library never reports a signature as verified.

## Resource limits

Inputs beyond `Limits` are rejected with `LimitExceeded`. Default limits are
32 KiB input, 1000 lines, 4096 bytes per physical line, 1000 fields, and 2048
bytes per value. The input, line-count, and value limits follow RFC 9116
Section 5.4 defensive guidance; the physical-line and field-count caps are
project choices, not protocol maxima.

## CLI

- Input is passed through `--text`; there is no `--file` or URL retrieval.
- `fresh` and `audit` require explicit `--now`, so runs are deterministic.
- Output is JSON except for `generate`, which prints security.txt text.

## Authorization

A security.txt file provides contact information. Its presence or absence does
not grant or deny permission to scan, attack, or test a system.
