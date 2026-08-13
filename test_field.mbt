// Field registry, URI scheme checks and language-tag validation tests.

///|
test "standard_field_name is case-insensitive for all nine fields" {
  assert_opt_str_eq(standard_field_name("contact"), Some("Contact"))
  assert_opt_str_eq(standard_field_name("CONTACT"), Some("Contact"))
  assert_opt_str_eq(standard_field_name("cOnTaCt"), Some("Contact"))
  assert_opt_str_eq(standard_field_name("expires"), Some("Expires"))
  assert_opt_str_eq(standard_field_name("EXPIRES"), Some("Expires"))
  assert_opt_str_eq(standard_field_name("canonical"), Some("Canonical"))
  assert_opt_str_eq(standard_field_name("encryption"), Some("Encryption"))
  assert_opt_str_eq(
    standard_field_name("acknowledgments"),
    Some("Acknowledgments"),
  )
  assert_opt_str_eq(standard_field_name("policy"), Some("Policy"))
  assert_opt_str_eq(standard_field_name("hiring"), Some("Hiring"))
  assert_opt_str_eq(
    standard_field_name("preferred-languages"),
    Some("Preferred-Languages"),
  )
  assert_opt_str_eq(
    standard_field_name("PREFERRED-LANGUAGES"),
    Some("Preferred-Languages"),
  )
}

///|
test "standard_field_name rejects unknown names and parse_standard_field maps variants" {
  assert_opt_str_eq(standard_field_name("contact-info"), None)
  assert_opt_str_eq(standard_field_name("security"), None)
  assert_opt_str_eq(standard_field_name(""), None)
  assert_false(is_standard_field_name("X-Custom"))
  assert_true(is_standard_field_name("contact"))
  match parse_standard_field("CONTACT", "mailto:a@example.com") {
    Some(Contact(value)) => assert_str_eq(value, "mailto:a@example.com")
    _ => fail("expected Contact")
  }
  match parse_standard_field("preferred-languages", "en, de") {
    Some(PreferredLanguages(value)) => assert_str_eq(value, "en, de")
    _ => fail("expected PreferredLanguages")
  }
  match parse_standard_field("X-Custom", "v") {
    None => ()
    _ => fail("expected None for an unknown field")
  }
}

///|
test "uri_scheme extracts known schemes and None without a prefix" {
  assert_opt_str_eq(uri_scheme("mailto:security@example.com"), Some("mailto"))
  assert_opt_str_eq(uri_scheme("https://example.com/x"), Some("https"))
  assert_opt_str_eq(uri_scheme("HTTP://example.com"), Some("http"))
  assert_opt_str_eq(uri_scheme("openpgp4fpr:1234ABCD"), Some("openpgp4fpr"))
  assert_opt_str_eq(uri_scheme("tel:+1-555-0100"), Some("tel"))
  assert_opt_str_eq(uri_scheme("urn:example:test"), Some("urn"))
  assert_opt_str_eq(uri_scheme("example.com/path"), None)
  assert_opt_str_eq(uri_scheme(""), None)
  assert_opt_str_eq(uri_scheme("1abc:x"), None)
  assert_opt_str_eq(uri_scheme(":x"), None)
}

///|
test "check_uri accepts minimal absolute URIs and rejects malformed ones" {
  assert_true(check_uri("mailto:security@example.com") is Ok(_))
  assert_true(
    check_uri("https://example.com/.well-known/security.txt") is Ok(_),
  )
  assert_true(check_uri("openpgp4fpr:1234ABCD1234ABCD") is Ok(_))
  assert_true(check_uri("example.com/path") is Err(_))
  assert_true(check_uri("https:") is Err(_))
  assert_true(check_uri("") is Err(_))
}

///|
test "check_uri rejects spaces and control characters" {
  assert_true(check_uri("mailto:a b@example.com") is Err(_))
  assert_true(check_uri("https://example.com/\u{1}") is Err(_))
}

///|
test "check_uri_scheme enforces the allow-list" {
  assert_true(
    check_uri_scheme("https://example.com/key", ["https"], "Encryption", 1, 0)
    is Ok(_),
  )
  match
    check_uri_scheme("mailto:a@example.com", ["https"], "Encryption", 1, 0) {
    Ok(_) => fail("expected an InvalidScheme error")
    Err(err) => assert_err_kind(err, InvalidScheme)
  }
}

///|
test "encryption_allowed_schemes covers RFC 9116 schemes" {
  let allowed = encryption_allowed_schemes()
  assert_int_eq(allowed.length(), 3)
  assert_true(allowed.contains("https"))
  assert_true(allowed.contains("dns"))
  assert_true(allowed.contains("openpgp4fpr"))
}

///|
test "check_language_tag accepts common tags" {
  for tag in ["en", "de", "en-US", "zh-Hans-CN", "x-private", "es-419"] {
    if check_language_tag(tag) is Err(_) {
      fail("expected '\{tag}' to be accepted")
    }
  }
}

///|
test "check_language_tag rejects malformed and overlong tags" {
  assert_true(check_language_tag("") is Err(_))
  assert_true(check_language_tag("e") is Err(_))
  assert_true(check_language_tag("en-") is Err(_))
  assert_true(check_language_tag("en_US") is Err(_))
  assert_true(check_language_tag("-en") is Err(_))
  assert_true(check_language_tag("en--US") is Err(_))
  let tag = "en-\{"a".repeat(34)}"
  assert_true(tag.length() > 35)
  assert_true(check_language_tag(tag) is Err(_))
}

///|
test "split_preferred_languages trims and skips empty parts" {
  let tags = split_preferred_languages(" en , de, fr ,")
  assert_int_eq(tags.length(), 3)
  assert_str_eq(tags[0], "en")
  assert_str_eq(tags[1], "de")
  assert_str_eq(tags[2], "fr")
}

///|
test "check_field_value accepts every valid field form" {
  assert_true(check_field_value(Contact("mailto:a@example.com"), 0, 0) is Ok(_))
  assert_true(
    check_field_value(
      Canonical("https://example.com/.well-known/security.txt"),
      0,
      0,
    )
    is Ok(_),
  )
  assert_true(
    check_field_value(Encryption("https://example.com/key.txt"), 0, 0) is Ok(_),
  )
  assert_true(check_field_value(Encryption("openpgp4fpr:1234"), 0, 0) is Ok(_))
  assert_true(
    check_field_value(Encryption("dns:key.example?type=OPENPGPKEY"), 0, 0)
    is Ok(_),
  )
  assert_true(
    check_field_value(Acknowledgments("https://example.com/thanks"), 0, 0)
    is Ok(_),
  )
  assert_true(
    check_field_value(Policy("https://example.com/policy"), 0, 0) is Ok(_),
  )
  assert_true(
    check_field_value(Hiring("https://example.com/jobs"), 0, 0) is Ok(_),
  )
  assert_true(check_field_value(Expires("2027-01-01T00:00:00Z"), 0, 0) is Ok(_))
  assert_true(check_field_value(PreferredLanguages("en, de"), 0, 0) is Ok(_))
  assert_true(check_field_value(Extension("X-Test", "anything"), 0, 0) is Ok(_))
}

///|
test "check_field_value rejects invalid per-field values" {
  match check_field_value(Contact("not a uri"), 0, 0) {
    Ok(_) => fail("expected InvalidUri")
    Err(err) => assert_err_kind(err, InvalidUri)
  }
  match check_field_value(Encryption("mailto:a@example.com"), 0, 0) {
    Ok(_) => ()
    Err(_) => fail("RFC 9116 does not define a closed Encryption scheme list")
  }
  match check_field_value(Policy("http://example.com/policy"), 0, 0) {
    Ok(_) => fail("expected InvalidScheme for an insecure web URI")
    Err(err) => assert_err_kind(err, InvalidScheme)
  }
  match check_field_value(Expires("tomorrow"), 0, 0) {
    Ok(_) => fail("expected InvalidDateTime")
    Err(err) => assert_err_kind(err, InvalidDateTime)
  }
  match check_field_value(PreferredLanguages("e"), 0, 0) {
    Ok(_) => fail("expected InvalidLanguage")
    Err(err) => assert_err_kind(err, InvalidLanguage)
  }
}
