// Parser tests through the public API: document structure, line handling, field splitting, encodings, positions and syntax errors.

///|
test "parser accepts a full valid document and keeps extension fields" {
  let document = unwrap_parse(valid_document())
  assert_int_eq(document.field_count(), 3)
  assert_int_eq(document.standard_field_count(), 3)
  assert_int_eq(document.extension_field_count(), 0)
  assert_int_eq(document.contacts().length(), 1)
  assert_int_eq(document.comments().length(), 1)
  let with_extensions = unwrap_parse(
    "X-One: 1\nContact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nX-Two: 2\n",
  )
  let extensions = with_extensions.extensions()
  assert_int_eq(extensions.length(), 2)
  assert_str_eq(extensions[0].name, "X-One")
  assert_str_eq(extensions[0].value, "1")
  assert_str_eq(extensions[1].name, "X-Two")
  assert_int_eq(with_extensions.extension_field_count(), 2)
}

///|
test "parser preserves field order and positions and normalizes name casing" {
  let input = "Contact: mailto:a@example.com\nFoo-Bar: x\nExpires: 2027-01-01T00:00:00Z\n"
  let document = unwrap_parse(input)
  let entries = document.entries()
  assert_int_eq(entries.length(), 3)
  assert_str_eq(entries[0].field.name(), "Contact")
  assert_str_eq(entries[1].field.name(), "Foo-Bar")
  assert_str_eq(entries[2].field.name(), "Expires")
  assert_int_eq(entries[0].line, 1)
  assert_int_eq(entries[1].line, 2)
  assert_int_eq(entries[2].line, 3)
  assert_int_eq(entries[0].byte_offset, 0)
  assert_int_eq(
    entries[1].byte_offset,
    "Contact: mailto:a@example.com\n".length(),
  )
  assert_int_eq(
    entries[2].byte_offset,
    "Contact: mailto:a@example.com\nFoo-Bar: x\n".length(),
  )
  let mixed = unwrap_parse(
    "cOnTaCt: mailto:a@example.com\nEXPIRES: 2027-01-01T00:00:00Z\n",
  )
  assert_str_eq(mixed.fields()[0].name(), "Contact")
  assert_str_eq(mixed.fields()[1].name(), "Expires")
}

///|
test "parser accepts comments and blank lines" {
  let input = "# first\n\nContact: mailto:a@example.com\n# second\nExpires: 2027-01-01T00:00:00Z\n"
  let document = unwrap_parse(input)
  assert_int_eq(document.comments().length(), 2)
  assert_str_eq(document.comments()[0], " first")
  assert_str_eq(document.comments()[1], " second")
  assert_int_eq(document.field_count(), 2)
  assert_int_eq(document.line_count(), 5)
}

///|
test "parser accepts whitespace-only lines and requires SP after colon" {
  let document = unwrap_parse(
    " \t \nContact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\n",
  )
  assert_int_eq(document.field_count(), 2)
  assert_err_kind(
    expect_parse_error("Contact:\tmailto:a@example.com\n"),
    InvalidLine,
  )
  assert_err_kind(
    expect_parse_error("Contact:mailto:a@example.com\n"),
    InvalidLine,
  )
}

///|
test "parser accepts CRLF line endings and rejects stray carriage returns" {
  let document = unwrap_parse(
    "Contact: mailto:a@example.com\r\nExpires: 2027-01-01T00:00:00Z\r\n",
  )
  assert_int_eq(document.field_count(), 2)
  assert_str_eq(document.contacts()[0], "mailto:a@example.com")
  let err = expect_parse_error(
    "Contact: mailto:a@example.com\rExpires: 2027-01-01T00:00:00Z\n",
  )
  assert_err_kind(err, InvalidLine)
  assert_true(err.stage() == Line)
}

///|
test "parser strips a UTF-8 BOM" {
  let full = @utf8.encode(
    "\u{FEFF}Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\n",
  )
  let document = unwrap_parse_bytes(full, Limits::default())
  assert_int_eq(document.field_count(), 2)
  assert_str_eq(document.contacts()[0], "mailto:a@example.com")
  // The three BOM bytes still count towards byte_count.
  assert_int_eq(document.byte_count(), full.length())
}

///|
test "parser reports a missing colon with its position" {
  let err = expect_parse_error("Contact without any colon\n")
  assert_err_kind(err, MissingColon)
  assert_int_eq(err.line(), 1)
  assert_int_eq(err.column(), 26)
  assert_int_eq(err.byte_offset(), 0)
}

///|
test "parser splits at the first colon only and rejects invalid name characters" {
  let err = expect_parse_error("Contact mailto:a@example.com\n")
  // The first colon sits inside "mailto:", making "Contact mailto" the name.
  assert_err_kind(err, InvalidLine)
  assert_true(err.stage() == FieldName)
  let document = unwrap_parse("X-With-Url: https://example.com/x\n")
  assert_str_eq(document.fields()[0].value(), "https://example.com/x")
  let err_name = expect_parse_error("Foo_Bar: x\n")
  assert_err_kind(err_name, InvalidLine)
  assert_true(err_name.stage() == FieldName)
}

///|
test "parser rejects empty field names, empty values and control characters" {
  let err_name = expect_parse_error(": value\n")
  assert_err_kind(err_name, EmptyFieldName)
  let err_value = expect_parse_error("Contact:\n")
  assert_err_kind(err_value, EmptyFieldValue)
  let input = bytes_of([
    0x43, 0x6F, 0x6E, 0x74, 0x61, 0x63, 0x74, 0x3A, 0x20, 0x61, 0x00, 0x62, 0x0A,
  ])
  let err = expect_parse_bytes_error(input, Limits::default())
  assert_err_kind(err, InvalidLine)
  assert_true(err.stage() == FieldValue)
}

///|
test "parser accepts UTF-8 values, counts bytes and reports invalid UTF-8" {
  let input = "Contact: mailto:sécurité@example.com\nExpires: 2027-01-01T00:00:00Z\n"
  let document = unwrap_parse(input)
  assert_str_eq(document.contacts()[0], "mailto:sécurité@example.com")
  // Two accented characters add one extra byte each over the char count.
  assert_int_eq(document.byte_count(), input.length() + 2)
  assert_true(utf8_byte_len("é") == 2)
  // 0xFF is never valid UTF-8.
  let bad = bytes_of([0x43, 0x6F, 0xFF, 0x0A])
  let err = expect_parse_bytes_error(bad, Limits::default())
  assert_err_kind(err, InvalidUtf8)
  assert_int_eq(err.byte_offset(), 2)
}

///|
test "strict UTF-8 rejects overlong three-byte encodings and accepts E0 boundary" {
  let overlong = bytes_of([0x58, 0x3A, 0x20, 0xE0, 0x80, 0x80, 0x0A])
  assert_err_kind(
    expect_parse_bytes_error(overlong, Limits::default()),
    InvalidUtf8,
  )
  let valid_boundary = bytes_of([0x58, 0x3A, 0x20, 0xE0, 0xA0, 0x80, 0x0A])
  assert_true(
    parse_security_txt_bytes(valid_boundary, Limits::default()) is Ok(_),
  )
}

///|
test "preferred_contact returns the first Contact in document order" {
  let document = unwrap_parse(
    "Contact: mailto:first@example.com\nContact: https://second.example.com/security\nExpires: 2027-01-01T00:00:00Z\n",
  )
  match document.preferred_contact() {
    Some(uri) => assert_str_eq(uri, "mailto:first@example.com")
    None => fail("expected a preferred contact")
  }
  assert_int_eq(document.contacts().length(), 2)
}

///|
test "expires accessor parses the value with field positions" {
  let document = unwrap_parse(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\n",
  )
  match document.expires() {
    Ok(dt) => {
      assert_int_eq(dt.year(), 2027)
      assert_int_eq(dt.month(), 1)
    }
    Err(err) => fail("expected a parseable Expires: \{err.to_string()}")
  }
  match unwrap_parse("Contact: mailto:a@example.com\n").expires() {
    Ok(_) => fail("expected MissingExpires")
    Err(err) => assert_err_kind(err, MissingExpires)
  }
}
