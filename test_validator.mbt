// RFC 9116 validator tests: required fields, cardinality, per-field value
// constraints and the difference between validate and validate_all.

// The RFC 9116 Appendix A.1 example, reproduced for testing.
// Known errata in the published RFC (noted in THIRD_PARTY_NOTICES.md):
// the `Expires` value uses a lower-case 'z' and the second `Contact` value
// lacks a scheme — this library accepts both leniently.

///|
fn rfc9116_a1_example() -> String {
  "# Our security acknowledgements page\nContact: mailto:security@example.com\nContact: https://example.com/security-contact\nEncryption: https://example.com/pgp-key.txt\nAcknowledgments: https://example.com/hall-of-fame\nExpires: 2021-12-31T18:37:07z\n"
}

///|
test "validator accepts the RFC 9116 A.1 example" {
  let document = unwrap_parse(rfc9116_a1_example())
  assert_true(validate(document) is Ok(_))
  assert_int_eq(validate_all(document).length(), 0)
}

///|
test "validator accepts complete documents and extension fields" {
  let document = unwrap_parse(valid_document())
  assert_true(validate(document) is Ok(_))
  let with_extensions = unwrap_parse(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nX-Vendor-Info: anything goes\n",
  )
  assert_true(validate(with_extensions) is Ok(_))
}

///|
test "validator requires both Contact and Expires" {
  let no_contact = unwrap_parse("Expires: 2027-01-01T00:00:00Z\n")
  match validate(no_contact) {
    Ok(_) => fail("expected MissingContact")
    Err(err) => assert_err_kind(err, MissingContact)
  }
  let no_expires = unwrap_parse("Contact: mailto:a@example.com\n")
  match validate(no_expires) {
    Ok(_) => fail("expected MissingExpires")
    Err(err) => assert_err_kind(err, MissingExpires)
  }
}

///|
test "validator rejects duplicate Expires and Preferred-Languages fields" {
  let dup_expires = unwrap_parse(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nExpires: 2028-01-01T00:00:00Z\n",
  )
  match validate(dup_expires) {
    Ok(_) => fail("expected DuplicateExpires")
    Err(err) => assert_err_kind(err, DuplicateExpires)
  }
  let dup_languages = unwrap_parse(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nPreferred-Languages: en\nPreferred-Languages: de\n",
  )
  match validate(dup_languages) {
    Ok(_) => fail("expected DuplicatePreferredLanguages")
    Err(err) => assert_err_kind(err, DuplicatePreferredLanguages)
  }
}

///|
test "validator accepts repeatable optional fields" {
  let document = unwrap_parse(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nCanonical: https://a.example.com/.well-known/security.txt\nCanonical: https://b.example.com/.well-known/security.txt\nEncryption: https://a.example.com/key\nEncryption: https://b.example.com/key\nPolicy: https://a.example.com/policy\nPolicy: https://b.example.com/policy\nHiring: https://a.example.com/jobs\nHiring: https://b.example.com/jobs\n",
  )
  assert_true(validate(document) is Ok(_))
  assert_int_eq(document.canonicals().length(), 2)
}

///|
test "validator accepts repeated Contact and Acknowledgments fields" {
  let document = unwrap_parse(
    "Contact: mailto:a@example.com\nContact: mailto:b@example.com\nAcknowledgments: https://example.com/thanks1\nAcknowledgments: https://example.com/thanks2\nExpires: 2027-01-01T00:00:00Z\n",
  )
  assert_true(validate(document) is Ok(_))
  assert_int_eq(document.contacts().length(), 2)
  assert_int_eq(document.acknowledgments().length(), 2)
}

///|
test "validator permits RFC Encryption URI schemes and rejects insecure web URIs" {
  let https_doc = unwrap_parse(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nEncryption: https://example.com/key.txt\n",
  )
  assert_true(validate(https_doc) is Ok(_))
  let fpr_doc = unwrap_parse(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nEncryption: openpgp4fpr:5f2de5521c63a801ab59ccb603d0de1b\n",
  )
  assert_true(validate(fpr_doc) is Ok(_))
  let dns_doc = unwrap_parse(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nEncryption: dns:key.example?type=OPENPGPKEY\n",
  )
  assert_true(validate(dns_doc) is Ok(_))
  let mailto_doc = unwrap_parse(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nEncryption: mailto:a@example.com\n",
  )
  assert_true(validate(mailto_doc) is Ok(_))
  let http_doc = unwrap_parse(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nEncryption: http://example.com/key\n",
  )
  match validate(http_doc) {
    Ok(_) => fail("expected InvalidScheme")
    Err(err) => assert_err_kind(err, InvalidScheme)
  }
}

///|
test "validator rejects invalid URIs per field" {
  for
    field_name in [
      "Contact", "Canonical", "Acknowledgments", "Policy", "Hiring",
    ] {
    let input = "\{field_name}: not a uri\nExpires: 2027-01-01T00:00:00Z\n"
    let document = unwrap_parse(input)
    match validate(document) {
      Ok(_) => fail("expected InvalidUri for \{field_name}")
      Err(err) => assert_err_kind(err, InvalidUri)
    }
  }
}

///|
test "validator rejects malformed Expires and language tag values" {
  let bad_expires = unwrap_parse(
    "Contact: mailto:a@example.com\nExpires: next Tuesday\n",
  )
  match validate(bad_expires) {
    Ok(_) => fail("expected InvalidDateTime")
    Err(err) => assert_err_kind(err, InvalidDateTime)
  }
  let bad_language = unwrap_parse(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nPreferred-Languages: e\n",
  )
  match validate(bad_language) {
    Ok(_) => fail("expected InvalidLanguage")
    Err(err) => assert_err_kind(err, InvalidLanguage)
  }
}

///|
test "validate returns the first error while validate_all collects all" {
  let document = unwrap_parse(
    "Expires: nonsense\nExpires: 2027-01-01T00:00:00Z\nCanonical: not a uri\n",
  )
  // Per-field value errors (in document order), then MissingContact,
  // then DuplicateExpires.
  let all = validate_all(document)
  assert_true(all.length() >= 4)
  match validate(document) {
    Ok(_) => fail("expected the first error")
    Err(err) => assert_err_kind(err, InvalidDateTime)
  }
}
