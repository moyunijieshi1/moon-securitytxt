// OpenPGP cleartext-signature envelope tests: detection, extraction,
// dash-unescaping and malformed-envelope rejection. No signature is ever
// verified — the library only reports `SignedUnverified`.

///|
fn signed_fixture() -> String {
  "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nContact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEEfake-signature-block\n=\n-----END PGP SIGNATURE-----\n"
}

///|
test "signed envelope is detected, the cleartext parses and armor headers are captured" {
  let document = unwrap_parse(signed_fixture())
  assert_true(document.is_signed())
  assert_true(document.signature_state() == SignedUnverified)
  assert_int_eq(document.contacts().length(), 1)
  assert_str_eq(document.contacts()[0], "mailto:security@example.com")
  assert_str_eq(document.expires_value().unwrap(), "2027-01-01T00:00:00Z")
  let headers = document.armor_headers()
  assert_int_eq(headers.length(), 1)
  assert_str_eq(headers[0], "Hash: SHA256")
}

///|
test "unsigned input is not detected as signed" {
  let document = unwrap_parse(valid_document())
  assert_false(document.is_signed())
  assert_true(document.signature_state() == Unsigned)
  assert_int_eq(document.armor_headers().length(), 0)
}

///|
test "dash-escaped cleartext is unescaped" {
  // RFC 4880: a cleartext comment starting with '-' is written as "- " + line.
  let input = "-----BEGIN PGP SIGNED MESSAGE-----\n\n- # comment written through dash-escaping\nContact: mailto:a@example.com\n-----BEGIN PGP SIGNATURE-----\n\nfake\n-----END PGP SIGNATURE-----\n"
  let document = unwrap_parse(input)
  assert_int_eq(document.comments().length(), 1)
  assert_str_eq(
    document.comments()[0],
    " comment written through dash-escaping",
  )
}

///|
test "malformed envelopes are rejected with InvalidSignatureEnvelope" {
  // Armor headers must be followed by a blank line.
  let no_blank = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\nContact: mailto:a@example.com\n"
  let err1 = expect_parse_error(no_blank)
  assert_err_kind(err1, InvalidSignatureEnvelope)
  // The signature begin marker is required.
  let no_begin = "-----BEGIN PGP SIGNED MESSAGE-----\n\nContact: mailto:a@example.com\n"
  let err2 = expect_parse_error(no_begin)
  assert_err_kind(err2, InvalidSignatureEnvelope)
  // The signature end marker is required.
  let no_end = "-----BEGIN PGP SIGNED MESSAGE-----\n\nContact: mailto:a@example.com\n-----BEGIN PGP SIGNATURE-----\n\nfake\n"
  let err3 = expect_parse_error(no_end)
  assert_err_kind(err3, InvalidSignatureEnvelope)
  // Content after the signature block is not part of the cleartext.
  let trailing = "\{signed_fixture()}Contact: mailto:evil@example.com\n"
  let err4 = expect_parse_error(trailing)
  assert_err_kind(err4, InvalidSignatureEnvelope)
}

///|
test "extract_cleartext returns the joined body for signed input" {
  match extract_cleartext(signed_fixture()) {
    Ok(Some(body)) => {
      assert_true(body.has_prefix("Contact: mailto:security@example.com\n"))
      assert_true(body.has_suffix("\n-----BEGIN PGP SIGNATURE-----") == false)
    }
    _ => fail("expected extracted cleartext")
  }
}

///|
test "extract_cleartext returns None for unsigned input" {
  match extract_cleartext(valid_document()) {
    Ok(None) => ()
    _ => fail("expected None for unsigned input")
  }
}
