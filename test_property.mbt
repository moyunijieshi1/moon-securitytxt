// Deterministic property-style tests: exhaustive grids over generated inputs
// rather than randomized fuzzing; each test asserts its exact case count.

///|
fn assert_true_msg(value : Bool, message : String) -> Unit raise {
  if !value {
    fail(message)
  }
}

///|
/// Render offset minutes as an RFC 3339 suffix.
fn offset_string(minutes : Int) -> String {
  if minutes == 0 {
    "Z"
  } else {
    let sign = if minutes < 0 { "-" } else { "+" }
    let total = if minutes < 0 { -minutes } else { minutes }
    "\{sign}\{pad2(total / 60)}:\{pad2(total % 60)}"
  }
}

///|
test "property: parse-format-parse round-trips a datetime grid" {
  let years = [1970, 2024]
  let months = [1, 4, 12]
  let days = [1, 28]
  let hours = [0, 23]
  let offsets = [0, 480, -300]
  let mut cases = 0
  for year in years {
    for month in months {
      for day in days {
        for hour in hours {
          for offset in offsets {
            let input = "\{pad4(year)}-\{pad2(month)}-\{pad2(day)}T\{pad2(hour)}:30:45\{offset_string(offset)}"
            match parse_rfc3339(input) {
              Ok(dt1) =>
                match parse_rfc3339(dt1.format_rfc3339()) {
                  Ok(dt2) =>
                    assert_true_msg(
                      dt1.to_epoch_nanos() == dt2.to_epoch_nanos(),
                      input,
                    )
                  Err(err) =>
                    fail(
                      "re-parse of '\{dt1.format_rfc3339()}' failed: \{err.to_string()}",
                    )
                }
              Err(err) =>
                fail("grid value '\{input}' failed: \{err.to_string()}")
            }
            cases += 1
          }
        }
      }
    }
  }
  assert_int_eq(cases, 72)
}

///|
test "property: calendar arithmetic is consistent across 1900..1944" {
  let mut cases = 0
  let mut year = 1900
  while year < 1945 {
    let feb = days_in_month(year, 2)
    assert_int_eq(feb, if is_leap_year(year) { 29 } else { 28 })
    let year_days = (days_from_civil(year + 1, 1, 1) -
    days_from_civil(year, 1, 1)).to_int()
    assert_int_eq(year_days, if is_leap_year(year) { 366 } else { 365 })
    cases += 2
    year += 1
  }
  assert_int_eq(cases, 90)
}

///|
test "property: numeric offsets shift the epoch by exactly their minutes" {
  let mut cases = 0
  let mut hour = 0
  while hour < 24 {
    let utc = unwrap_datetime(
      parse_rfc3339("\{pad4(2026)}-08-13T\{pad2(hour)}:15:00Z"),
    )
    let east = unwrap_datetime(
      parse_rfc3339("\{pad4(2026)}-08-13T\{pad2(hour)}:15:00+08:00"),
    )
    let diff = east.to_epoch_nanos() - utc.to_epoch_nanos()
    assert_true(diff == -8L * 3600L * 1_000_000_000L)
    cases += 1
    hour += 1
  }
  assert_int_eq(cases, 24)
}

///|
test "property: generated documents round-trip through serialize" {
  let mut cases = 0
  let mut i = 0
  while i < 40 {
    let nl = if i % 2 == 0 { "\n" } else { "\r\n" }
    let mut doc = ""
    let contacts = i % 3 + 1
    let mut c = 0
    while c < contacts {
      doc = "\{doc}Contact: mailto:user\{c}@example.com\{nl}"
      c += 1
    }
    if i % 4 == 1 {
      doc = "\{doc}Canonical: https://example.com/.well-known/security.txt\{nl}"
    }
    if i % 4 == 2 {
      doc = "\{doc}Policy: https://example.com/policy\{nl}"
    }
    let extensions = i % 3
    let mut e = 0
    while e < extensions {
      doc = "\{doc}X-Ext\{e}: v\{i}\{nl}"
      e += 1
    }
    if i % 5 == 0 {
      doc = "\{doc}# generated comment\{nl}"
    }
    doc = "\{doc}Expires: 2027-01-01T00:00:00Z\{nl}"
    let parsed = unwrap_parse(doc)
    let serialized = serialize_security_txt(parsed)
    let again = unwrap_parse(serialized)
    assert_int_eq(again.field_count(), parsed.field_count())
    assert_int_eq(again.comments().length(), parsed.comments().length())
    cases += 1
    i += 1
  }
  assert_int_eq(cases, 40)
}

///|
test "property: uri_scheme classifies a fixed scheme grid" {
  let with_scheme = [
    "mailto:a", "https://example.com", "http://example.com", "openpgp4fpr:1234",
    "tel:+1-555", "urn:test:x", "ftp://example.com", "ssh://example.com", "custom+v1:x",
    "a.b-c:x", "ABC:x", "x:y", "git+ssh://host", "z39.50:y", "scheme-name:x",
  ]
  let without_scheme = [
    "example.com/path", "", "1abc:x", ":x", "ab_c:x", "ab c:x", "://host", "no-colon-here",
    "a?b:c", "x y:z",
  ]
  let mut cases = 0
  for value in with_scheme {
    match uri_scheme(value) {
      Some(scheme) => assert_true(scheme.length() > 0)
      None => fail("expected a scheme in '\{value}'")
    }
    cases += 1
  }
  for value in without_scheme {
    match uri_scheme(value) {
      Some(_) => fail("expected no scheme in '\{value}'")
      None => ()
    }
    cases += 1
  }
  assert_int_eq(cases, 25)
}

///|
test "property: language tag grid is classified deterministically" {
  let valid_tags = [
    "en", "de", "fr-CA", "en-US", "zh-Hans", "zh-Hans-CN", "es-419", "x-test", "aa",
    "zz", "en-a-b-c-d",
  ]
  let invalid_tags = [
    "", "e", "1en", "en-", "-en", "en--US", "en_US", "en ", " en", "en-us_", "123456",
    "e-n", "ab--cd", "ab-",
  ]
  let mut cases = 0
  for tag in valid_tags {
    if check_language_tag(tag) is Err(_) {
      fail("expected '\{tag}' to be accepted")
    }
    cases += 1
  }
  for tag in invalid_tags {
    if check_language_tag(tag) is Ok(_) {
      fail("expected '\{tag}' to be rejected")
    }
    cases += 1
  }
  assert_int_eq(cases, 25)
}

///|
test "property: generated documents parse and validate across a fixed grid" {
  let expires = unwrap_datetime(make_utc(2027, 1, 1, 0, 0, 0))
  let mut cases = 0
  let mut i = 0
  while i < 150 {
    let mut builder = new_builder()
      .contact("mailto:user\{i}@example.com")
      .expires(expires)
    if i % 2 == 0 {
      builder = builder.policy("https://example.com/policy/\{i}")
    }
    if i % 3 == 0 {
      builder = builder.preferred_languages(["en", "de"])
    }
    if i % 5 == 0 {
      builder = builder.extension("X-Case", "\{i}")
    }
    if i % 7 == 0 {
      builder = builder.contact("tel:+1-555-\{1000 + i}")
    }
    match builder.build() {
      Err(err) => fail("generated case \{i} failed: \{err.to_string()}")
      Ok(document) => {
        let parsed = unwrap_parse(serialize_security_txt(document))
        assert_true(validate(parsed) is Ok(_))
        assert_int_eq(parsed.contacts().length(), document.contacts().length())
      }
    }
    cases += 1
    i += 1
  }
  assert_int_eq(cases, 150)
}
