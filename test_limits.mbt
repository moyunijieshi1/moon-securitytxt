// Resource-limit tests: the preset profiles and the enforcement of every individual cap during parsing.

///|
test "default limits use the documented values" {
  let d = Limits::default()
  assert_int_eq(d.max_input_bytes(), 32 * 1024)
  assert_int_eq(d.max_lines(), 1000)
  assert_int_eq(d.max_line_bytes(), 4096)
  assert_int_eq(d.max_fields(), 1000)
  assert_int_eq(d.max_field_value_bytes(), 2048)
}

///|
test "strict and permissive limits bracket the defaults" {
  let s = Limits::strict()
  let p = Limits::permissive()
  let d = Limits::default()
  assert_true(s.max_input_bytes() < d.max_input_bytes())
  assert_true(s.max_lines() < d.max_lines())
  assert_true(s.max_line_bytes() < d.max_line_bytes())
  assert_true(s.max_fields() < d.max_fields())
  assert_true(s.max_field_value_bytes() < d.max_field_value_bytes())
  assert_true(p.max_input_bytes() > d.max_input_bytes())
  assert_true(p.max_fields() > d.max_fields())
  assert_true(p.max_field_value_bytes() > d.max_field_value_bytes())
}

///|
test "custom limits replace positive values and fall back otherwise" {
  let c = Limits::custom(100, 0, 50, -1, 20)
  assert_int_eq(c.max_input_bytes(), 100)
  assert_int_eq(c.max_lines(), Limits::default().max_lines())
  assert_int_eq(c.max_line_bytes(), 50)
  assert_int_eq(c.max_fields(), Limits::default().max_fields())
  assert_int_eq(c.max_field_value_bytes(), 20)
}

///|
test "input size limit is enforced" {
  let limits = Limits::custom(100, 100, 200, 100, 100)
  let err = expect_parse_bytes_error(bytes_of_ascii("x".repeat(101)), limits)
  assert_err_kind(err, LimitExceeded)
  assert_true(err.stage() == Limit)
}

///|
test "line count and line byte limits are enforced" {
  let lines = Limits::custom(100, 5, 100, 100, 100)
  let err_lines = expect_parse_bytes_error(
    bytes_of_ascii("\n\n\n\n\n\n"),
    lines,
  )
  assert_err_kind(err_lines, LimitExceeded)
  let bytes = Limits::custom(1000, 100, 50, 100, 100)
  let err_bytes = expect_parse_bytes_error(
    bytes_of_ascii("x".repeat(60)),
    bytes,
  )
  assert_err_kind(err_bytes, LimitExceeded)
  assert_int_eq(err_bytes.line(), 1)
}

///|
test "field count and field value byte limits are enforced" {
  let fields = Limits::custom(1000, 100, 100, 2, 100)
  let err_fields = expect_parse_bytes_error(
    bytes_of_ascii("A: 1\nB: 2\nC: 3\n"),
    fields,
  )
  assert_err_kind(err_fields, LimitExceeded)
  let value_bytes = Limits::custom(1000, 100, 100, 100, 20)
  let input = "Contact: \{"a".repeat(30)}\nExpires: 2027-01-01T00:00:00Z\n"
  let err_value = expect_parse_bytes_error(bytes_of_ascii(input), value_bytes)
  assert_err_kind(err_value, LimitExceeded)
}

///|
test "documents within the limits parse normally" {
  let limits = Limits::custom(512, 20, 100, 10, 200)
  let document = unwrap_parse_bytes(bytes_of_ascii(valid_document()), limits)
  assert_int_eq(document.field_count(), 3)
}

///|
/// ASCII-only Bytes builder used by the limit tests.
fn bytes_of_ascii(input : String) -> Bytes {
  @utf8.encode(input)
}
