// RFC 9116 semantic validation. The parser owns syntax; this module owns the
// RFC field constraints: per-field value formats, required fields, singleton cardinality.

///|
/// Validate a document; fails with the first error found.
pub fn validate(document : SecurityTxt) -> Result[Unit, SecurityTxtError] {
  let errors = validate_all(document)
  if errors.length() == 0 {
    Ok(())
  } else {
    Err(errors[0])
  }
}

///|
/// Collect every RFC violation in a document; empty when valid. Deterministic order.
pub fn validate_all(document : SecurityTxt) -> Array[SecurityTxtError] {
  let errors : Array[SecurityTxtError] = []
  let contact_lines : Array[Int] = []
  let expires_lines : Array[Int] = []
  let pl_lines : Array[Int] = []
  for entry in document.entries() {
    match entry.field {
      Contact(_) => contact_lines.push(entry.line)
      Expires(_) => expires_lines.push(entry.line)
      PreferredLanguages(_) => pl_lines.push(entry.line)
      _ => ()
    }
    match check_field_value(entry.field, entry.line, entry.byte_offset) {
      Ok(_) => ()
      Err(err) => errors.push(err)
    }
  }
  if contact_lines.is_empty() {
    errors.push(missing_error(MissingContact, "document has no Contact field"))
  }
  if expires_lines.is_empty() {
    errors.push(missing_error(MissingExpires, "document has no Expires field"))
  }
  if expires_lines.length() > 1 {
    errors.push(dup_error(DuplicateExpires, "Expires", expires_lines[0]))
  }
  if pl_lines.length() > 1 {
    errors.push(
      dup_error(DuplicatePreferredLanguages, "Preferred-Languages", pl_lines[0]),
    )
  }
  errors
}

///|
/// Build a required-field error with unknown position.
fn missing_error(
  kind : SecurityTxtErrorKind,
  message : String,
) -> SecurityTxtError {
  security_txt_error(Validation, kind, 0, 0, -1, message)
}

///|
/// Build a duplicate-field error pointing at the first occurrence.
fn dup_error(
  kind : SecurityTxtErrorKind,
  name : String,
  first_line : Int,
) -> SecurityTxtError {
  security_txt_error(
    Validation,
    kind,
    first_line,
    1,
    -1,
    "\{name} MUST NOT appear more than once (first occurrence at line \{first_line})",
  )
}
