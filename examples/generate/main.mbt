// Example: generate a validated security.txt document with the builder. `build` runs the RFC validator.

///|
fn main {
  match @lib.parse_rfc3339("2027-01-01T00:00:00Z") {
    Ok(expires) =>
      match
        @lib.new_builder()
        .comment(" Our security contact page")
        .contact("mailto:security@example.com")
        .contact("https://example.com/security-contact")
        .expires(expires)
        .canonical("https://example.com/.well-known/security.txt")
        .encryption("https://example.com/pgp-key.txt")
        .acknowledgments("https://example.com/hall-of-fame")
        .policy("https://example.com/security-policy")
        .preferred_languages(["en", "de"])
        .extension("X-Vendor", "example")
        .build() {
        Ok(document) => {
          let text = @lib.serialize_security_txt(document) // Serialized output ends with a newline; trim it for println.
          let trimmed = if text.has_suffix("\n") {
            text[0:text.length() - 1].to_owned()
          } else {
            text
          }
          println(trimmed)
          match document.expires() {
            Ok(dt) =>
              println(
                "(generated Expires parses back to \{dt.format_rfc3339()})",
              )
            Err(err) => println("(unexpected: \{err.message()})")
          }
        }
        Err(err) => println("generation failed: \{err.to_string()}")
      }
    Err(err) => println("bad expiry: \{err.message()}")
  }
}
