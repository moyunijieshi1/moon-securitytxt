// Field-name registry and per-field value checks.
// URI and language-tag handling here is minimal: just enough for RFC 9116
// security.txt fields, not a general browser-grade URL parser (see docs/limitations.md).

///|
/// ASCII lower-case a string; field names are ASCII, so no Unicode case folding needed.
fn ascii_lower(s : String) -> String {
  let sb = StringBuilder::new(size_hint=s.length())
  for c in s {
    sb.write_char(c.to_ascii_lowercase())
  }
  sb.to_string()
}

///|
/// Look up a case-insensitive field name; returns the canonical name.
pub fn standard_field_name(name : String) -> String? {
  match ascii_lower(name) {
    "contact" => Some("Contact")
    "expires" => Some("Expires")
    "canonical" => Some("Canonical")
    "encryption" => Some("Encryption")
    "acknowledgments" => Some("Acknowledgments")
    "policy" => Some("Policy")
    "hiring" => Some("Hiring")
    "preferred-languages" => Some("Preferred-Languages")
    _ => None
  }
}

///|
/// True when the name (any case) is one of the nine standard fields.
pub fn is_standard_field_name(name : String) -> Bool {
  standard_field_name(name) is Some(_)
}

///|
/// Map a case-insensitive name to the matching standard field, or None.
pub fn parse_standard_field(name : String, value : String) -> SecurityField? {
  match standard_field_name(name) {
    Some("Contact") => Some(Contact(value))
    Some("Expires") => Some(Expires(value))
    Some("Canonical") => Some(Canonical(value))
    Some("Encryption") => Some(Encryption(value))
    Some("Acknowledgments") => Some(Acknowledgments(value))
    Some("Policy") => Some(Policy(value))
    Some("Hiring") => Some(Hiring(value))
    Some("Preferred-Languages") => Some(PreferredLanguages(value))
    _ => None
  }
}

///|
/// Lower-case URI scheme of a value with a scheme-like prefix
/// (ALPHA *(ALPHA / DIGIT / "+" / "-" / ".") ":").
pub fn uri_scheme(value : String) -> String? {
  let mut i = 0
  for c in value {
    if c == ':' && i > 0 {
      return Some(ascii_lower(slice(value, 0, i)))
    }
    let ok = c.is_ascii_alphabetic() ||
      (i > 0 && (c.is_ascii_digit() || c == '+' || c == '-' || c == '.'))
    if !ok {
      return None
    }
    i += 1
  }
  None
}

///|
/// True when the value contains control characters (C0 except HTAB, or DEL)
/// or literal spaces, which are not permitted in a URI.
pub fn contains_uri_illegal(value : String) -> Bool {
  for c in value {
    let n = c.to_int()
    if (n < 0x20 && n != 0x09) || n == 0x7F || n == 0x20 {
      return true
    }
  }
  false
}

///|
/// Minimal absolute-URI syntax check: scheme present, non-empty remainder, no control
/// characters or spaces. Scheme policy (e.g. the `https` requirement on `Encryption`)
/// is checked separately via `check_uri_scheme`.
pub fn check_uri(value : String) -> Result[Unit, SecurityTxtError] {
  if contains_uri_illegal(value) {
    return Err(
      security_txt_error(
        Uri,
        InvalidUri,
        0,
        1,
        0,
        "URI contains control characters or spaces",
      ),
    )
  }
  let scheme = match uri_scheme(value) {
    None =>
      return Err(
        security_txt_error(
          Uri,
          InvalidUri,
          0,
          1,
          0,
          "value is not an absolute URI (no valid scheme prefix)",
        ),
      )
    Some(s) => s
  }
  let len = scheme.length() + 1
  if value.length() == len {
    return Err(
      security_txt_error(
        Uri,
        InvalidUri,
        0,
        len + 1,
        len,
        "URI has an empty scheme-specific part",
      ),
    )
  }
  Ok(())
}

///|
/// Enforce a per-field scheme allow-list; `InvalidScheme` on violation.
pub fn check_uri_scheme(
  value : String,
  allowed : Array[String],
  field_name : String,
  line : Int,
  byte_offset : Int,
) -> Result[Unit, SecurityTxtError] {
  let scheme = match uri_scheme(value) {
    None =>
      return Err(
        security_txt_error(
          Uri,
          InvalidScheme,
          line,
          1,
          byte_offset + 1,
          "\{field_name} value has no URI scheme",
        ),
      )
    Some(s) => s
  }
  for allowed_scheme in allowed {
    if scheme == allowed_scheme {
      return Ok(())
    }
  }
  Err(
    security_txt_error(
      Uri,
      InvalidScheme,
      line,
      1,
      byte_offset + 1,
      "\{field_name} scheme '\{scheme}' is not allowed here (allowed: \{allowed.join(", ")}",
    ),
  )
}

///|
/// Common schemes demonstrated by RFC 9116 for `Encryption`.
/// This is informational: RFC 9116 also demonstrates `dns:` and does not define
/// a closed allow-list. Validation only forbids insecure `http:` web URIs.
pub fn encryption_allowed_schemes() -> Array[String] {
  ["https", "dns", "openpgp4fpr"]
}

///|
/// Validate one field value against its RFC 9116 constraints. `line` and `byte_offset`
/// position the field in the original input; they are 0 for generated documents.
pub fn check_field_value(
  field : SecurityField,
  line : Int,
  byte_offset : Int,
) -> Result[Unit, SecurityTxtError] {
  match field {
    Contact(value) => check_uri_at(value, "Contact", line, byte_offset)
    Canonical(value) => check_uri_at(value, "Canonical", line, byte_offset)
    Encryption(value) => check_uri_at(value, "Encryption", line, byte_offset)
    Acknowledgments(value) =>
      check_uri_at(value, "Acknowledgments", line, byte_offset)
    Policy(value) => check_uri_at(value, "Policy", line, byte_offset)
    Hiring(value) => check_uri_at(value, "Hiring", line, byte_offset)
    Expires(value) => check_expires_at(value, line, byte_offset)
    PreferredLanguages(value) =>
      check_language_tags_at(value, line, byte_offset)
    Extension(_, _) => Ok(())
  }
}

///|
/// URI check with error positions rewritten to the field location.
fn check_uri_at(
  value : String,
  field_name : String,
  line : Int,
  byte_offset : Int,
) -> Result[Unit, SecurityTxtError] {
  match check_uri(value) {
    Ok(_) =>
      match uri_scheme(value) {
        Some("http") =>
          Err(
            security_txt_error(
              Uri,
              InvalidScheme,
              line,
              1,
              byte_offset + 1,
              "\{field_name}: web URIs must use https",
            ),
          )
        _ => Ok(())
      }
    Err(err) =>
      Err(relocate(err, line, byte_offset, "\{field_name}: \{err.message()}"))
  }
}

///|
fn check_expires_at(
  value : String,
  line : Int,
  byte_offset : Int,
) -> Result[Unit, SecurityTxtError] {
  match parse_rfc3339(value) {
    Ok(_) => Ok(())
    Err(err) => Err(relocate(err, line, byte_offset, err.message()))
  }
}

///|
/// Split a `Preferred-Languages` value into trimmed tags.
pub fn split_preferred_languages(value : String) -> Array[String] {
  let out : Array[String] = []
  for part in value.split(",") {
    let trimmed = part.trim()
    if trimmed.length() > 0 {
      out.push(trimmed.to_owned())
    }
  }
  out
}

///|
/// Validate a language tag against the project-defined RFC 5646 subset: a 2-8 alpha
/// primary subtag (or private-use `x`), optional `-`-separated 1-8 alphanumeric subtags,
/// at most 35 characters. No registry lookup is performed.
pub fn check_language_tag(tag : String) -> Result[Unit, SecurityTxtError] {
  if tag.length() == 0 {
    return Err(
      security_txt_error(
        Language,
        InvalidLanguage,
        0,
        1,
        0,
        "language tag is empty",
      ),
    )
  }
  if tag.length() > 35 {
    return Err(
      security_txt_error(
        Language,
        InvalidLanguage,
        0,
        1,
        0,
        "language tag exceeds 35 characters",
      ),
    )
  }
  let mut first = true
  for subtag in tag.split("-") {
    if first {
      let primary = subtag.to_owned()
      if !((primary.length() >= 2 && primary.length() <= 8) || primary == "x") {
        return Err(
          security_txt_error(
            Language,
            InvalidLanguage,
            0,
            1,
            0,
            "primary language subtag must be 2-8 letters (or the private-use singleton 'x')",
          ),
        )
      }
      for c in primary {
        if !c.is_ascii_alphabetic() {
          return Err(
            security_txt_error(
              Language,
              InvalidLanguage,
              0,
              1,
              0,
              "primary language subtag must be alphabetic",
            ),
          )
        }
      }
      first = false
    } else {
      if subtag.length() < 1 || subtag.length() > 8 {
        return Err(
          security_txt_error(
            Language,
            InvalidLanguage,
            0,
            1,
            0,
            "language subtag must be 1-8 alphanumeric characters",
          ),
        )
      }
      for c in subtag {
        if !c.is_ascii_alphabetic() && !c.is_ascii_digit() {
          return Err(
            security_txt_error(
              Language,
              InvalidLanguage,
              0,
              1,
              0,
              "language subtag must be alphanumeric",
            ),
          )
        }
      }
    }
  }
  Ok(())
}

///|
/// Validate every tag of a `Preferred-Languages` value, positioned at the field.
fn check_language_tags_at(
  value : String,
  line : Int,
  byte_offset : Int,
) -> Result[Unit, SecurityTxtError] {
  let tags = split_preferred_languages(value)
  if tags.length() == 0 {
    return Err(
      security_txt_error(
        Language,
        InvalidLanguage,
        line,
        1,
        byte_offset + 1,
        "Preferred-Languages lists no language tags",
      ),
    )
  }
  for tag in tags {
    match check_language_tag(tag) {
      Ok(_) => ()
      Err(err) =>
        return Err(
          relocate(err, line, byte_offset, "\{err.message()} (tag '\{tag}')"),
        )
    }
  }
  Ok(())
}

///|
fn relocate(
  err : SecurityTxtError,
  line : Int,
  byte_offset : Int,
  message : String,
) -> SecurityTxtError {
  security_txt_error(
    err.stage(),
    err.kind(),
    line,
    err.column() + 1,
    byte_offset + 1 + err.byte_offset(),
    message,
  )
}
