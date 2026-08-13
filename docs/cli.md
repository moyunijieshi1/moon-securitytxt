# securitytxt-tool CLI

`securitytxt-tool` is the command-line front end of the library. All
input arrives via `--text` (or as the first positional argument); the
tool never opens files and never touches the network.

```console
moon run ./cmd/securitytxt-tool --target wasm-gc -- <command> [options]
```

## Commands

| Command | Purpose | Required options |
| --- | --- | --- |
| `parse` | Parse and summarize a document | `--text` |
| `validate` | RFC and supplied retrieval-context validation; prints every error | `--text` |
| `fresh` | Freshness check against `--now` | `--text --now` |
| `generate` | Generate a validated document (prints the text) | `--contact --expires` |
| `audit` | Advisory findings against `--now` and the context | `--text --now` |
| `stats` | Structural statistics | `--text` |
| `version` / `--version` | Version banner | — |
| `help` / `--help` | Usage | — |

## Shared options

| Option | Meaning |
| --- | --- |
| `--text <document>` | The security.txt content |
| `--limits <default\|strict\|permissive>` | Parser resource limits |
| `--now <rfc3339>` | Reference time for `fresh`/`audit` (deterministic; the tool never reads the clock) |
| `--retrieval-uri <uri>` | Retrieval URI for context checks and `Canonical` comparison |
| `--content-type <type>` | Content-Type observed at retrieval |

## Generate options

`--contact` and `--acknowledgments` are repeatable (order kept);
`--comment`, `--extension` too. Singleton options (`--expires`,
`--canonical`, `--encryption`, `--policy`, `--hiring`,
`--preferred-languages`) keep the last occurrence.

```console
moon run ./cmd/securitytxt-tool --target wasm-gc -- generate \
  --contact "mailto:security@example.com" \
  --expires 2027-01-01T00:00:00Z \
  --policy "https://example.com/policy" \
  --preferred-languages "en, de"
```

`--extension` expects `Name:value` (split at the first colon).
`--preferred-languages` expects a comma-separated tag list.
`--expires` must be an RFC 3339 date-time; the builder then validates
the whole document and prints the serialized text.

## Output

Every command prints exactly one JSON object per line, except
`generate`, which prints the document text. Errors look like:

```json
{"ok":false,"error":{"stage":"Validation","kind":"MissingContact","line":0,"column":0,"offset":-1,"message":"document has no Contact field"}}
```

Option-level failures use `MissingOption`, `UnknownOption`,
`UnknownCommand` or `InvalidNow` kinds.

## Examples

```console
moon run ./cmd/securitytxt-tool --target wasm-gc -- validate --text "Contact: mailto:a@example.com`nExpires: 2027-01-01T00:00:00Z`n"
# {"ok":true,"valid":true,"errors":[]}

moon run ./cmd/securitytxt-tool --target wasm-gc -- fresh --now 2026-08-13T00:00:00Z --text "Contact: mailto:a@example.com`nExpires: 2027-01-01T00:00:00Z`n"
# {"ok":true,"now":"2026-08-13T00:00:00Z","expires":"2027-01-01T00:00:00Z","expired":false,"seconds_until_expiry":12182400,"expires_within_30_days":false}
```
