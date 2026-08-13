// Example: parse a signed security.txt document and summarize it. Reports SignedUnverified, never verified.

///|
fn main {
  let input = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" +
    "# Our security contact page\nContact: mailto:security@example.com\n" +
    "Contact: https://example.com/security-contact\nEncryption: https://example.com/pgp-key.txt\n" +
    "Expires: 2027-01-01T00:00:00Z\nX-Vendor: example\n" +
    "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEEfake-signature-block\n=\n-----END PGP SIGNATURE-----\n"
  match @lib.parse_security_txt(input) {
    Ok(document) => {
      println("fields: \{document.field_count()}")
      println("standard fields: \{document.standard_field_count()}")
      println("extension fields: \{document.extension_field_count()}")
      println("contacts: \{document.contacts().length()}")
      println("comments: \{document.comments().length()}")
      println("signed: \{document.is_signed()}")
      println("signature state: SignedUnverified (never 'verified')")
      println("armor headers: \{document.armor_headers().length()}")
      match document.preferred_contact() {
        Some(uri) => println("preferred contact: \{uri}")
        None => println("preferred contact: none")
      }
      println("--- serialized round-trip ---")
      let text = @lib.serialize_security_txt(document) // Serialized output ends with a newline; trim it for println.
      let trimmed = if text.has_suffix("\n") {
        text[0:text.length() - 1].to_owned()
      } else {
        text
      }
      println(trimmed)
    }
    Err(err) => println("parse failed: \{err.to_string()}")
  }
}
