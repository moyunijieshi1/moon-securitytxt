// Defensive RFC 9116 security.txt parser. Syntax only: byte decoding, line structure,
// comments, field name/value separation, resource limits. RFC field constraints (URI
// schemes, date formats, cardinality) belong to the validator; advisory observations
// belong to the audit layer.

///|
/// Parse a security.txt document with default limits.
pub fn parse_security_txt(
  input : String,
) -> Result[SecurityTxt, SecurityTxtError] {
  parse_security_txt_with_limits(input, Limits::default())
}

///|
/// Parse a security.txt document with explicit limits.
pub fn parse_security_txt_with_limits(
  input : String,
  limits : Limits,
) -> Result[SecurityTxt, SecurityTxtError] {
  parse_security_txt_bytes(@utf8.encode(input), limits)
}

///|
/// Parse raw bytes with limits; invalid UTF-8 reports InvalidUtf8 with byte offsets.
pub fn parse_security_txt_bytes(
  input : Bytes,
  limits : Limits,
) -> Result[SecurityTxt, SecurityTxtError] {
  Ok(parse_inner(input, limits)) catch {
    e => Err(unwrap_security_txt_error(e))
  }
}

///|
/// Split text into LF lines, stripping one CR, with byte offsets; no trailing line.
pub fn split_lines_text(input : String) -> (Array[String], Array[Int]) {
  let lines : Array[String] = []
  let offsets : Array[Int] = []
  let mut start = 0
  let mut i = 0
  while i < input.length() {
    let c = char_at_index(input, i)
    if c == '\n' ||
      (
        c == '\r' &&
        i + 1 < input.length() &&
        char_at_index(input, i + 1) == '\n'
      ) {
      lines.push(slice(input, start, i))
      offsets.push(start)
      start = i + (if c == '\n' { 1 } else { 2 })
      i += if c == '\n' { 1 } else { 2 }
    } else {
      i += 1
    }
  }
  if start < input.length() {
    lines.push(slice(input, start, input.length()))
    offsets.push(start)
  }
  (lines, offsets)
}

///|
fn char_at_index(s : String, at : Int) -> Char {
  let mut i = 0
  for c in s {
    if i == at {
      return c
    }
    i += 1
  }
  '?'
}

///|
/// Parse the raw bytes. Every failure raises SecurityTxtError.
fn parse_inner(input : Bytes, limits : Limits) -> SecurityTxt raise {
  let byte_count = input.length()
  if byte_count > limits.max_input_bytes {
    raise security_txt_error(
      Limit,
      LimitExceeded,
      1,
      1,
      limits.max_input_bytes,
      "input size \{byte_count} exceeds max_input_bytes \{limits.max_input_bytes}",
    )
  }
  let raw = input.to_fixedarray()
  // Split into line byte slices on LF; strip one trailing CR; reject stray CR.
  let line_starts : Array[Int] = []
  let line_ends : Array[Int] = []
  let mut line_start = 0
  let mut i = 0
  let mut current_line = 0
  while i < byte_count {
    let b = raw[i].to_int()
    if b == 0x0A || b == 0x0D {
      if b == 0x0D {
        // CR is only legal immediately before LF.
        if i + 1 >= byte_count || raw[i + 1].to_int() != 0x0A {
          raise security_txt_error(
            Line,
            InvalidLine,
            current_line + 1,
            i - line_start + 1,
            i,
            "stray carriage return (line endings must be LF or CRLF)",
          )
        }
      }
      line_starts.push(line_start)
      line_ends.push(i)
      line_start = i + (if b == 0x0D { 2 } else { 1 })
      current_line += 1
      if b == 0x0D {
        i += 1
      }
    }
    i += 1
  }
  if line_start < byte_count {
    line_starts.push(line_start)
    line_ends.push(byte_count)
    current_line += 1
  }
  let line_count = current_line
  if line_count > limits.max_lines {
    raise security_txt_error(
      Limit,
      LimitExceeded,
      1,
      1,
      0,
      "line count \{line_count} exceeds max_lines \{limits.max_lines}",
    )
  }
  // Strip a UTF-8 BOM from the very start of the input.
  let bom = byte_count >= 3 &&
    raw[0].to_int() == 0xEF &&
    raw[1].to_int() == 0xBB &&
    raw[2].to_int() == 0xBF
  // Decode each line, validating UTF-8 with byte-accurate offsets.
  let lines : Array[String] = []
  let offsets : Array[Int] = []
  for j = 0; j < line_starts.length(); j = j + 1 {
    let mut s = line_starts[j]
    if bom && j == 0 && s < 3 {
      s = 3
    }
    let line_bytes = line_ends[j] - s
    if line_bytes > limits.max_line_bytes {
      raise security_txt_error(
        Limit,
        LimitExceeded,
        j + 1,
        1,
        line_starts[j],
        "line \{j + 1} exceeds max_line_bytes \{limits.max_line_bytes}",
      )
    }
    let decoded = decode_utf8_strict(
      raw,
      s,
      line_ends[j],
      j + 1,
      line_starts[j],
    )
    lines.push(decoded)
    offsets.push(line_starts[j])
  }
  // Detect a signed envelope on the first line.
  let mut signature = SignatureState::Unsigned
  let mut armor_headers : Array[String] = []
  let mut field_lines : Array[String] = []
  let mut field_offsets : Array[Int] = []
  match split_signed_envelope(lines, offsets) {
    Ok(None) => {
      field_lines = lines
      field_offsets = offsets
    }
    Ok(Some(payload)) => {
      signature = SignedUnverified
      armor_headers = payload.armor_headers()
      field_lines = payload.cleartext_lines()
      field_offsets = payload.cleartext_offsets()
    }
    Err(err) => raise err
  }
  // Process field lines.
  let entries : Array[SecurityFieldEntry] = []
  let comments : Array[String] = []
  let mut field_count = 0
  for j = 0; j < field_lines.length(); j = j + 1 {
    let line = field_lines[j]
    // RFC 9116 permits blank lines whose EOL is preceded by WSP.
    if line.trim().length() == 0 {
      continue
    }
    if line.has_prefix("#") {
      comments.push(slice(line, 1, line.length()))
      continue
    }
    field_count += 1
    if field_count > limits.max_fields {
      raise security_txt_error(
        Limit,
        LimitExceeded,
        j + 1,
        1,
        field_offsets[j],
        "field count exceeds max_fields \{limits.max_fields}",
      )
    }
    let (name, value) = split_field_line(line, j + 1, field_offsets[j])
    if utf8_byte_len(value) > limits.max_field_value_bytes {
      raise security_txt_error(
        Limit,
        LimitExceeded,
        j + 1,
        1,
        field_offsets[j],
        "field value exceeds max_field_value_bytes \{limits.max_field_value_bytes}",
      )
    }
    let field = match parse_standard_field(name, value) {
      Some(f) => f
      None => Extension(name, value)
    }
    entries.push(security_field_entry(field, j + 1, field_offsets[j]))
  }
  security_txt(
    entries, comments, signature, armor_headers, line_count, byte_count,
  )
}

///|
fn is_ws(c : Char) -> Bool {
  c == ' ' || c == '\t'
}

///|
/// Split a field line into (name, value) at the first colon.
fn split_field_line(
  line : String,
  line_no : Int,
  byte_offset : Int,
) -> (String, String) raise {
  let mut colon = -1
  let mut i = 0
  for c in line {
    if c == ':' {
      colon = i
      break
    }
    i += 1
  }
  if colon < 0 {
    raise security_txt_error(
      Line,
      MissingColon,
      line_no,
      line.length() + 1,
      byte_offset,
      "field line has no ':' separator",
    )
  }
  let name = slice(line, 0, colon)
  if name.length() == 0 {
    raise security_txt_error(
      FieldName,
      EmptyFieldName,
      line_no,
      1,
      byte_offset,
      "field name is empty",
    )
  }
  for c in name {
    if !c.is_ascii_alphabetic() && !c.is_ascii_digit() && c != '-' {
      raise security_txt_error(
        FieldName,
        InvalidLine,
        line_no,
        1,
        byte_offset,
        "field name contains characters outside ALPHA / DIGIT / '-'",
      )
    }
  }
  // RFC 9116 field syntax is `Name: value`; whitespace after the colon is syntax, not
  // part of the value. Surrounding SP / HTAB is stripped from the stored value.
  let raw_value = slice(line, colon + 1, line.length())
  if raw_value.length() == 0 {
    raise security_txt_error(
      FieldValue,
      EmptyFieldValue,
      line_no,
      colon + 2,
      byte_offset + colon + 1,
      "field value is empty",
    )
  }
  if char_at_index(raw_value, 0) != ' ' {
    raise security_txt_error(
      Line,
      InvalidLine,
      line_no,
      colon + 2,
      byte_offset + colon + 1,
      "field separator must be followed by SP",
    )
  }
  let mut value_start = 0
  while value_start < raw_value.length() &&
        is_ws(char_at_index(raw_value, value_start)) {
    value_start += 1
  }
  let mut value_end = raw_value.length()
  while value_end > value_start &&
        is_ws(char_at_index(raw_value, value_end - 1)) {
    value_end -= 1
  }
  let value = slice(raw_value, value_start, value_end)
  if value.length() == 0 {
    raise security_txt_error(
      FieldValue,
      EmptyFieldValue,
      line_no,
      colon + 2,
      byte_offset + colon + 1,
      "field value is empty",
    )
  }
  for c in value {
    if c.to_int() < 0x20 || c.to_int() == 0x7F {
      raise security_txt_error(
        FieldValue,
        InvalidLine,
        line_no,
        colon + 2 + value_start,
        byte_offset + colon + 1 + value_start,
        "field value contains a control character",
      )
    }
  }
  (name, value)
}

///|
pub fn utf8_byte_len(s : String) -> Int {
  let mut n = 0
  for c in s {
    n += char_utf8_len(c)
  }
  n
}

///|
pub fn char_utf8_len(c : Char) -> Int {
  let n = c.to_int()
  if n < 0x80 {
    1
  } else if n < 0x800 {
    2
  } else if n < 0x10000 {
    3
  } else {
    4
  }
}

///|
fn is_cont(b : Int) -> Bool {
  b >= 0x80 && b <= 0xBF
}

///|
/// Strict UTF-8 decoder with byte-accurate diagnostics.
fn decode_utf8_strict(
  raw : FixedArray[Byte],
  start : Int,
  end : Int,
  line : Int,
  base_offset : Int,
) -> String raise {
  let sb = StringBuilder::new(size_hint=end - start)
  let mut i = start
  let mut chars = 0
  while i < end {
    let b0 = raw[i].to_int()
    if b0 < 0x80 {
      sb.write_char(b0.unsafe_to_char())
      i += 1
    } else if b0 <= 0xBF {
      raise invalid_utf8(
        line,
        chars + 1,
        base_offset + i - start,
        "unexpected continuation byte",
      )
    } else if b0 >= 0xC2 && b0 <= 0xDF {
      if i + 1 >= end {
        raise invalid_utf8(
          line,
          chars + 1,
          base_offset + i - start,
          "truncated 2-byte sequence",
        )
      }
      let b1 = raw[i + 1].to_int()
      if !is_cont(b1) {
        raise invalid_utf8(
          line,
          chars + 1,
          base_offset + i - start,
          "invalid continuation byte",
        )
      }
      let cp = ((b0 & 0x1F) << 6) | (b1 & 0x3F)
      sb.write_char(cp.unsafe_to_char())
      i += 2
    } else if b0 <= 0xEF {
      if i + 2 >= end {
        raise invalid_utf8(
          line,
          chars + 1,
          base_offset + i - start,
          "truncated 3-byte sequence",
        )
      }
      let b1 = raw[i + 1].to_int()
      let b2 = raw[i + 2].to_int()
      let ok = is_cont(b1) &&
        is_cont(b2) &&
        (if b0 == 0xE0 {
          b1 >= 0xA0
        } else if b0 == 0xED {
          b1 <= 0x9F
        } else {
          true
        })
      if !ok {
        raise invalid_utf8(
          line,
          chars + 1,
          base_offset + i - start,
          "invalid 3-byte sequence (overlong, surrogate or bad continuation)",
        )
      }
      let cp = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F)
      sb.write_char(cp.unsafe_to_char())
      i += 3
    } else if b0 <= 0xF4 {
      if i + 3 >= end {
        raise invalid_utf8(
          line,
          chars + 1,
          base_offset + i - start,
          "truncated 4-byte sequence",
        )
      }
      let b1 = raw[i + 1].to_int()
      let b2 = raw[i + 2].to_int()
      let b3 = raw[i + 3].to_int()
      let ok = is_cont(b1) &&
        is_cont(b2) &&
        is_cont(b3) &&
        (if b0 == 0xF0 {
          b1 >= 0x90 && b1 <= 0x9F
        } else if b0 == 0xF4 {
          b1 <= 0x8F
        } else {
          true
        })
      if !ok {
        raise invalid_utf8(
          line,
          chars + 1,
          base_offset + i - start,
          "invalid 4-byte sequence (overlong, above U+10FFFF or bad continuation)",
        )
      }
      let cp = ((b0 & 0x07) << 18) |
        ((b1 & 0x3F) << 12) |
        ((b2 & 0x3F) << 6) |
        (b3 & 0x3F)
      sb.write_char(cp.unsafe_to_char())
      i += 4
    } else {
      raise invalid_utf8(
        line,
        chars + 1,
        base_offset + i - start,
        "byte is not valid UTF-8",
      )
    }
    chars += 1
  }
  sb.to_string()
}

///|
fn invalid_utf8(
  line : Int,
  column : Int,
  offset : Int,
  message : String,
) -> SecurityTxtError {
  security_txt_error(Input, InvalidUtf8, line, column, offset, message)
}
