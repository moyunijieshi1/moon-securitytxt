// Retrieval-context validation tests: HTTPS well-known location, content
// type checks and the Canonical comparison. The library never fetches.

///|
fn canonical_document() -> SecurityTxt raise {
  unwrap_parse(
    "Canonical: https://example.com/.well-known/security.txt\nContact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\n",
  )
}

///|
test "empty and well-formed retrieval contexts validate" {
  assert_true(validate_context(empty_context()) is Ok(_))
  let context = security_txt_context(
    Some("https://example.com/.well-known/security.txt"),
    Some("text/plain; charset=utf-8"),
  )
  assert_true(validate_context(context) is Ok(_))
}

///|
test "non-https retrieval URIs and wrong paths are rejected" {
  let http_context = security_txt_context(
    Some("http://example.com/.well-known/security.txt"),
    None,
  )
  match validate_context(http_context) {
    Ok(_) => fail("expected InvalidContext")
    Err(err) => assert_err_kind(err, InvalidContext)
  }
  let wrong_path = security_txt_context(
    Some("https://example.com/other.txt"),
    None,
  )
  assert_true(validate_context(wrong_path) is Err(_))
}

///|
test "query and fragment are ignored for the path check" {
  let context = security_txt_context(
    Some("https://example.com/.well-known/security.txt?download=1#top"),
    None,
  )
  assert_true(validate_context(context) is Ok(_))
}

///|
test "text/plain content types validate" {
  assert_true(
    validate_context(security_txt_context(None, Some("text/plain"))) is Ok(_),
  )
  assert_true(
    validate_context(
      security_txt_context(None, Some("text/plain; charset=utf-8")),
    )
    is Ok(_),
  )
}

///|
test "wrong media type and charset are rejected" {
  assert_true(
    validate_context(security_txt_context(None, Some("text/html"))) is Err(_),
  )
  assert_true(
    validate_context(
      security_txt_context(None, Some("text/plain; charset=iso-8859-1")),
    )
    is Err(_),
  )
}

///|
test "canonical comparison passes for a matching retrieval URI" {
  let context = security_txt_context(
    Some("https://example.com/.well-known/security.txt"),
    None,
  )
  assert_true(
    validate_retrieval_context(canonical_document(), context) is Ok(_),
  )
}

///|
test "canonical comparison accepts any listed canonical URI" {
  let document = unwrap_parse(
    "Canonical: https://one.example/.well-known/security.txt\nCanonical: https://two.example/.well-known/security.txt\nContact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\n",
  )
  let context = security_txt_context(
    Some("https://two.example/.well-known/security.txt"),
    None,
  )
  assert_true(validate_retrieval_context(document, context) is Ok(_))
}

///|
test "canonical comparison fails for mismatching or absent retrieval URIs" {
  let context = security_txt_context(
    Some("https://other.example.com/.well-known/security.txt"),
    None,
  )
  match validate_retrieval_context(canonical_document(), context) {
    Ok(_) => fail("expected ContextMismatch")
    Err(err) => assert_err_kind(err, ContextMismatch)
  }
  match validate_retrieval_context(canonical_document(), empty_context()) {
    Ok(_) => fail("expected ContextMismatch")
    Err(err) => assert_err_kind(err, ContextMismatch)
  }
}

///|
test "documents without Canonical skip the comparison" {
  let document = unwrap_parse(valid_document())
  assert_true(validate_retrieval_context(document, empty_context()) is Ok(_))
  assert_true(
    validate_retrieval_context(
      document,
      security_txt_context(Some("https://anything.example.com/x"), None),
    )
    is Ok(_),
  )
}
