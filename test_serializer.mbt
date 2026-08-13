// Serializer and generator tests: deterministic rendering, round-trips and the validated SecurityTxtBuilder.

///|
test "serializer round-trips a parsed document and always ends with a newline" {
  let original = unwrap_parse(valid_document())
  let text = serialize_security_txt(original)
  let again = unwrap_parse(text)
  assert_int_eq(again.field_count(), original.field_count())
  assert_int_eq(again.comments().length(), original.comments().length())
  let mut i = 0
  while i < original.fields().length() {
    assert_str_eq(again.fields()[i].name(), original.fields()[i].name())
    assert_str_eq(again.fields()[i].value(), original.fields()[i].value())
    i += 1
  }
  assert_true(text.has_suffix("\n"))
}

///|
test "serializer emits comments first and normalizes field names" {
  let commented = unwrap_parse(
    "# one\n# two\nContact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\n",
  )
  assert_str_eq(
    serialize_security_txt(commented),
    "# one\n# two\nContact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\n",
  )
  let mixed_case = unwrap_parse(
    "cOnTaCt: mailto:a@example.com\nexpires: 2027-01-01T00:00:00Z\n",
  )
  assert_str_eq(
    serialize_security_txt(mixed_case),
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\n",
  )
}

///|
test "serializer keeps extension fields" {
  let document = unwrap_parse(
    "X-One: 1\nContact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\n",
  )
  let text = serialize_security_txt(document)
  assert_true(text.has_prefix("X-One: 1\n"))
}

///|
test "builder produces a valid minimal document" {
  let expires = unwrap_datetime(make_utc(2027, 1, 1, 0, 0, 0))
  match new_builder().contact("mailto:a@example.com").expires(expires).build() {
    Ok(document) => {
      assert_int_eq(document.field_count(), 2)
      assert_true(validate(document) is Ok(_))
      assert_str_eq(document.fields()[0].name(), "Contact")
      assert_str_eq(document.fields()[1].name(), "Expires")
    }
    Err(err) => fail("build failed: \{err.to_string()}")
  }
}

///|
test "builder assembles fields in the documented fixed order" {
  let expires = unwrap_datetime(make_utc(2027, 1, 1, 0, 0, 0))
  match
    new_builder()
    .hiring("https://example.com/jobs")
    .canonical("https://example.com/.well-known/security.txt")
    .contact("mailto:b@example.com")
    .policy("https://example.com/policy")
    .contact("mailto:a@example.com")
    .extension("X-Last", "v")
    .encryption("https://example.com/key.txt")
    .acknowledgments("https://example.com/thanks")
    .preferred_languages(["en", "de"])
    .expires(expires)
    .build() {
    Ok(document) => {
      let names : Array[String] = []
      for field in document.fields() {
        names.push(field.name())
      }
      assert_str_eq(
        names.join(","),
        "Contact,Contact,Expires,Canonical,Encryption,Acknowledgments,Policy,Hiring,Preferred-Languages,X-Last",
      )
    }
    Err(err) => fail("build failed: \{err.to_string()}")
  }
}

///|
test "builder joins preferred languages with commas" {
  let expires = unwrap_datetime(make_utc(2027, 1, 1, 0, 0, 0))
  match
    new_builder()
    .contact("mailto:a@example.com")
    .expires(expires)
    .preferred_languages(["en", "de"])
    .build() {
    Ok(document) =>
      assert_str_eq(document.preferred_languages_value().unwrap(), "en, de")
    Err(err) => fail("build failed: \{err.to_string()}")
  }
}

///|
test "builder rejects missing required fields and invalid field values" {
  let expires = unwrap_datetime(make_utc(2027, 1, 1, 0, 0, 0))
  match new_builder().expires(expires).build() {
    Ok(_) => fail("expected MissingContact")
    Err(err) => assert_err_kind(err, MissingContact)
  }
  match new_builder().contact("mailto:a@example.com").build() {
    Ok(_) => fail("expected MissingExpires")
    Err(err) => assert_err_kind(err, MissingExpires)
  }
  match new_builder().contact("not a uri").expires(expires).build() {
    Ok(_) => fail("expected InvalidUri")
    Err(err) => assert_err_kind(err, InvalidUri)
  }
}

///|
test "builder rejects extension and comment content that would break syntax" {
  let expires = unwrap_datetime(make_utc(2027, 1, 1, 0, 0, 0))
  let base = new_builder().contact("mailto:a@example.com").expires(expires)
  assert_true(base.extension("Bad Name", "value").build() is Err(_))
  assert_true(base.extension("X-Test", "").build() is Err(_))
  assert_true(base.extension("X-Test", "line\nbreak").build() is Err(_))
  assert_true(base.comment("one\ntwo").build() is Err(_))
}
