// Deterministic serializer plus a validated generator: `serialize_security_txt` renders
// comments first, then fields in stored order with canonical names and LF endings.
// `SecurityTxtBuilder` builds typed documents; `build` validates, returning the first error.

///|
/// Serialize to canonical text: comments then fields in stored order, LF line endings.
pub fn serialize_security_txt(document : SecurityTxt) -> String {
  let sb = StringBuilder::new(size_hint=document.byte_count() + 64)
  for comment in document.comments() {
    sb.write_string("#" + comment + "\n")
  }
  for entry in document.entries() {
    sb.write_string(entry.field.name() + ": " + entry.field.value() + "\n")
  }
  sb.to_string()
}

///|
/// Builder for generating valid security.txt documents.
pub struct SecurityTxtBuilder {
  contacts : Array[String]
  mut expires : DateTime?
  mut canonical : String?
  mut encryption : String?
  acknowledgments : Array[String]
  mut policy : String?
  mut hiring : String?
  mut preferred_languages : Array[String]?
  extensions : Array[ExtensionField]
  comments : Array[String]
}

///|
/// Start a new builder.
pub fn new_builder() -> SecurityTxtBuilder {
  {
    contacts: [],
    expires: None,
    canonical: None,
    encryption: None,
    acknowledgments: [],
    policy: None,
    hiring: None,
    preferred_languages: None,
    extensions: [],
    comments: [],
  }
}

///|
/// Add a `Contact` field. Multiple calls preserve call order.
pub fn SecurityTxtBuilder::contact(
  self : SecurityTxtBuilder,
  uri : String,
) -> SecurityTxtBuilder {
  self.contacts.push(uri)
  self
}

///|
/// Set the `Expires` field from a `DateTime` (formatted as RFC 3339).
pub fn SecurityTxtBuilder::expires(
  self : SecurityTxtBuilder,
  expires : DateTime,
) -> SecurityTxtBuilder {
  self.expires = Some(expires)
  self
}

///|
/// Set the `Canonical` field.
pub fn SecurityTxtBuilder::canonical(
  self : SecurityTxtBuilder,
  uri : String,
) -> SecurityTxtBuilder {
  self.canonical = Some(uri)
  self
}

///|
/// Set the `Encryption` field.
pub fn SecurityTxtBuilder::encryption(
  self : SecurityTxtBuilder,
  uri : String,
) -> SecurityTxtBuilder {
  self.encryption = Some(uri)
  self
}

///|
/// Add an `Acknowledgments` field.
pub fn SecurityTxtBuilder::acknowledgments(
  self : SecurityTxtBuilder,
  uri : String,
) -> SecurityTxtBuilder {
  self.acknowledgments.push(uri)
  self
}

///|
/// Set the `Policy` field.
pub fn SecurityTxtBuilder::policy(
  self : SecurityTxtBuilder,
  uri : String,
) -> SecurityTxtBuilder {
  self.policy = Some(uri)
  self
}

///|
/// Set the `Hiring` field.
pub fn SecurityTxtBuilder::hiring(
  self : SecurityTxtBuilder,
  uri : String,
) -> SecurityTxtBuilder {
  self.hiring = Some(uri)
  self
}

///|
/// Set `Preferred-Languages`; tags are joined with `, `.
pub fn SecurityTxtBuilder::preferred_languages(
  self : SecurityTxtBuilder,
  tags : Array[String],
) -> SecurityTxtBuilder {
  self.preferred_languages = Some(tags)
  self
}

///|
/// Add an extension field.
pub fn SecurityTxtBuilder::extension(
  self : SecurityTxtBuilder,
  name : String,
  value : String,
) -> SecurityTxtBuilder {
  self.extensions.push(extension_field(name, value))
  self
}

///|
/// Add a comment line (without the leading `#`).
pub fn SecurityTxtBuilder::comment(
  self : SecurityTxtBuilder,
  text : String,
) -> SecurityTxtBuilder {
  self.comments.push(text)
  self
}

///|
/// Push an entry for `field` at `line` and return the next line number.
fn push_field(
  entries : Array[SecurityFieldEntry],
  field : SecurityField,
  line : Int,
) -> Int {
  entries.push(security_field_entry(field, line, 0))
  line + 1
}

///|
/// Push an optional entry (built by `make`) or leave `line` unchanged.
fn[T] push_opt(
  entries : Array[SecurityFieldEntry],
  opt : T?,
  line : Int,
  make : (T) -> SecurityField,
) -> Int {
  match opt {
    Some(v) => push_field(entries, make(v), line)
    None => line
  }
}

///|
/// Build and validate; fixed deterministic field order; errors are returned as-is.
pub fn SecurityTxtBuilder::build(
  self : SecurityTxtBuilder,
) -> Result[SecurityTxt, SecurityTxtError] {
  let entries : Array[SecurityFieldEntry] = []
  let mut line = 1
  for contact in self.contacts {
    line = push_field(entries, Contact(contact), line)
  }
  line = push_opt(entries, self.expires, line, fn(dt : DateTime) {
    Expires(dt.format_rfc3339())
  })
  line = push_opt(entries, self.canonical, line, fn(uri : String) {
    Canonical(uri)
  })
  line = push_opt(entries, self.encryption, line, fn(uri : String) {
    Encryption(uri)
  })
  for uri in self.acknowledgments {
    line = push_field(entries, Acknowledgments(uri), line)
  }
  line = push_opt(entries, self.policy, line, fn(uri : String) { Policy(uri) })
  line = push_opt(entries, self.hiring, line, fn(uri : String) { Hiring(uri) })
  line = push_opt(entries, self.preferred_languages, line, fn(tags) {
    PreferredLanguages(tags.join(", "))
  })
  for ext in self.extensions {
    line = push_field(entries, Extension(ext.name, ext.value), line)
  }
  let document = security_txt(entries, self.comments, Unsigned, [], line - 1, 0)
  let serialized = serialize_security_txt(document)
  let full = security_txt(
    entries,
    self.comments,
    Unsigned,
    [],
    line - 1,
    utf8_byte_len(serialized),
  )
  match validate(full) {
    Ok(_) =>
      // Validation intentionally ignores extension syntax and comments; a final
      // parser round-trip guarantees the generator can only emit legal text.
      match parse_security_txt(serialized) {
        Ok(_) => Ok(full)
        Err(err) => Err(err)
      }
    Err(err) => Err(err)
  }
}
