// Example: audit a document against a fixed `now` and a retrieval context. Findings are advisory only.

///|
fn main {
  match @lib.parse_rfc3339("2026-08-13T00:00:00Z") {
    Ok(now) => {
      let input = "Contact: mailto:security@example.com\nExpires: 2026-08-20T00:00:00Z\n" +
        "Canonical: https://example.com/.well-known/security.txt\nPolicy: http://example.com/security-policy\n" +
        "X-Custom-Field: anything\n"
      match @lib.parse_security_txt(input) {
        Ok(document) => {
          let context = @lib.security_txt_context(
            Some("https://example.com/.well-known/security.txt"),
            Some("text/plain; charset=utf-8"),
          )
          for finding in @lib.audit(document, now, context) {
            println(
              "[\{finding.severity().label()}] \{finding.kind().label()} " +
              "(line \{finding.line()}): \{finding.message()}",
            )
          }
        }
        Err(err) => println("parse failed: \{err.to_string()}")
      }
    }
    Err(err) => println("bad now: \{err.message()}")
  }
}
