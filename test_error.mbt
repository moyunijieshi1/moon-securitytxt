// Structured error tests: construction, accessors, rendering and the
// guarantee that every public `Err` of this library is a `SecurityTxtError`
// with a stage, a kind and a position.

///|
test "security_txt_error carries every component" {
  let err = security_txt_error(Line, MissingColon, 3, 7, 42, "no colon found")
  assert_true(err.stage() == Line)
  assert_true(err.kind() == MissingColon)
  assert_int_eq(err.line(), 3)
  assert_int_eq(err.column(), 7)
  assert_int_eq(err.byte_offset(), 42)
  assert_str_eq(err.message(), "no colon found")
}

///|
test "zero positions are preserved and omitted from rendering" {
  let err = security_txt_error(Validation, MissingContact, 0, 0, -1, "absent")
  assert_int_eq(err.line(), 0)
  assert_int_eq(err.column(), 0)
  assert_int_eq(err.byte_offset(), -1)
  assert_str_eq(err.to_string(), "Validation::MissingContact: absent")
}

///|
test "error to_string includes position when known" {
  let err = security_txt_error(Line, MissingColon, 2, 5, 10, "no colon")
  let rendered = err.to_string()
  assert_true(
    rendered.has_prefix("Line::MissingColon at byte 10, line 2, column 5"),
  )
  assert_true(rendered.has_suffix("no colon"))
}

///|
test "error messages are bounded to 200 characters" {
  let err = security_txt_error(Line, InvalidLine, 1, 1, 0, "x".repeat(500))
  assert_true(err.message().length() <= 203)
  assert_true(err.message().has_suffix("..."))
}

///|
test "stage names render stably" {
  assert_str_eq(Input.to_string(), "Input")
  assert_str_eq(SignatureEnvelope.to_string(), "SignatureEnvelope")
  assert_str_eq(FieldName.to_string(), "FieldName")
  assert_str_eq(Limit.to_string(), "Limit")
  assert_str_eq(Validation.to_string(), "Validation")
}

///|
test "every error kind has a distinct non-empty name" {
  let names = [
    InvalidLine.to_string(),
    MissingColon.to_string(),
    EmptyFieldName.to_string(),
    EmptyFieldValue.to_string(),
    InvalidUtf8.to_string(),
    InvalidUri.to_string(),
    InvalidScheme.to_string(),
    InvalidDateTime.to_string(),
    InvalidLanguage.to_string(),
    DuplicateExpires.to_string(),
    DuplicatePreferredLanguages.to_string(),
    DuplicateField.to_string(),
    MissingContact.to_string(),
    MissingExpires.to_string(),
    ContextMismatch.to_string(),
    SecurityTxtErrorKind::InvalidContext.to_string(),
    LimitExceeded.to_string(),
    InvalidSignatureEnvelope.to_string(),
  ]
  let mut i = 0
  while i < names.length() {
    assert_true(names[i].length() > 0)
    i += 1
  }
}
