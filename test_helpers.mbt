// Shared assertion and unwrap helpers for the named tests in this package.
//
// Kept deliberately small: each helper fails loudly with a readable message
// instead of silently passing, so a broken assertion never hides in noise.

///|
fn assert_true(value : Bool) -> Unit raise {
  if !value {
    fail("expected true")
  }
}

///|
fn assert_false(value : Bool) -> Unit raise {
  if value {
    fail("expected false")
  }
}

///|
fn assert_int_eq(actual : Int, expected : Int) -> Unit raise {
  if actual != expected {
    fail("expected \{expected}, got \{actual}")
  }
}

///|

///|
fn assert_str_eq(actual : String, expected : String) -> Unit raise {
  if actual != expected {
    fail("expected '\{expected}', got '\{actual}'")
  }
}

///|
fn assert_opt_str_eq(actual : String?, expected : String?) -> Unit raise {
  match (actual, expected) {
    (Some(a), Some(e)) => assert_str_eq(a, e)
    (None, None) => ()
    _ => fail("optional strings differ")
  }
}

///|
/// Parse successfully or fail the test with the parse error.
fn unwrap_parse(input : String) -> SecurityTxt raise {
  match parse_security_txt(input) {
    Ok(document) => document
    Err(err) => fail("parse failed unexpectedly: \{err.to_string()}")
  }
}

///|
/// Parse raw bytes successfully or fail the test with the parse error.
fn unwrap_parse_bytes(input : Bytes, limits : Limits) -> SecurityTxt raise {
  match parse_security_txt_bytes(input, limits) {
    Ok(document) => document
    Err(err) => fail("parse failed unexpectedly: \{err.to_string()}")
  }
}

///|
/// Require a parse error; fail the test when parsing succeeds.
fn expect_parse_error(input : String) -> SecurityTxtError raise {
  match parse_security_txt(input) {
    Ok(document) =>
      fail("expected a parse error, got \{document.field_count()} fields")
    Err(err) => err
  }
}

///|
/// Require a parse error for raw bytes; fail when parsing succeeds.
fn expect_parse_bytes_error(
  input : Bytes,
  limits : Limits,
) -> SecurityTxtError raise {
  match parse_security_txt_bytes(input, limits) {
    Ok(document) =>
      fail("expected a parse error, got \{document.field_count()} fields")
    Err(err) => err
  }
}

///|
/// Assert an error has exactly the expected kind.
fn assert_err_kind(
  err : SecurityTxtError,
  kind : SecurityTxtErrorKind,
) -> Unit raise {
  if err.kind() != kind {
    fail(
      "expected \{kind.to_string()}, got \{err.kind().to_string()}: \{err.message()}",
    )
  }
}

///|
/// A small, fully RFC-valid document used across the test suite.
fn valid_document() -> String {
  "# A valid example security.txt\nContact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00.000Z\nPreferred-Languages: en, de\n"
}

///|
/// Unwrap a DateTime result or fail.
fn unwrap_datetime(
  result : Result[DateTime, SecurityTxtError],
) -> DateTime raise {
  match result {
    Ok(dt) => dt
    Err(err) => fail("datetime construction failed: \{err.to_string()}")
  }
}

///|
/// True when the findings contain the given kind.
fn has_finding(findings : Array[AuditFinding], kind : AuditFindingKind) -> Bool {
  for finding in findings {
    if finding.kind() == kind {
      return true
    }
  }
  false
}

///| True when the result holds a value.

///| True when the result holds an error.

///|
/// Build raw bytes from integer values (mod 256), for invalid-UTF-8 inputs.
fn bytes_of(values : Array[Int]) -> Bytes {
  let out : Array[Byte] = []
  for v in values {
    out.push((v & 0xFF).to_byte())
  }
  Bytes::from_array(out)
}
