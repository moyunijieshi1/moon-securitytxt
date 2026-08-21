// Core semantic model for RFC 9116 security.txt documents. Field values are stored with the
// `Name:` syntax stripped; typed accessors parse on demand so the parser stays syntactic and
// the validator keeps sole ownership of RFC field constraints.

///|
/// A parsed field: standard fields carry raw values; unknown fields become `Extension`.
pub(all) enum SecurityField {
  Contact(String)
  Expires(String)
  Canonical(String)
  Encryption(String)
  Acknowledgments(String)
  Policy(String)
  Hiring(String)
  PreferredLanguages(String)
  Extension(String, String)
} derive(Eq, Debug)

///|
/// Signature state: the OpenPGP envelope is extracted but never verified.
pub(all) enum SignatureState {
  Unsigned
  SignedUnverified
} derive(Eq, Debug)

///|
/// An ordered field record with its position in the source file.
pub struct SecurityFieldEntry {
  field : SecurityField
  line : Int
  byte_offset : Int
} derive(Eq, Debug)

///|
/// An unknown (extension) field: RFC 9116 fields are extensible.
pub struct ExtensionField {
  name : String
  value : String
} derive(Eq, Debug)

///|
/// A parsed security.txt document; field order is preserved.
pub struct SecurityTxt {
  entries : Array[SecurityFieldEntry]
  comments : Array[String]
  signature : SignatureState
  armor_headers : Array[String]
  line_count : Int
  byte_count : Int
} derive(Debug)

///|
/// Construct a document. Prefer `parse_security_txt` or the generator; for tests.
pub fn security_txt(
  entries : Array[SecurityFieldEntry],
  comments : Array[String],
  signature : SignatureState,
  armor_headers : Array[String],
  line_count : Int,
  byte_count : Int,
) -> SecurityTxt {
  { entries, comments, signature, armor_headers, line_count, byte_count }
}

///|
/// Construct an ordered field record.
pub fn security_field_entry(
  field : SecurityField,
  line : Int,
  byte_offset : Int,
) -> SecurityFieldEntry {
  { field, line, byte_offset }
}

///|
/// Construct an extension field record.
pub fn extension_field(name : String, value : String) -> ExtensionField {
  { name, value }
}

///|
/// All fields in original document order.
pub fn SecurityTxt::fields(self : SecurityTxt) -> Array[SecurityField] {
  let out : Array[SecurityField] = []
  for entry in self.entries {
    out.push(entry.field)
  }
  out
}

///|
/// Ordered field records with positions.
pub fn SecurityTxt::entries(self : SecurityTxt) -> Array[SecurityFieldEntry] {
  self.entries
}

///|
/// All `Contact` values in original order.
pub fn SecurityTxt::contacts(self : SecurityTxt) -> Array[String] {
  let out : Array[String] = []
  for entry in self.entries {
    match entry.field {
      Contact(value) => out.push(value)
      _ => ()
    }
  }
  out
}

///|
/// The preferred contact: the first `Contact`, exactly as written (no scheme ranking).
pub fn SecurityTxt::preferred_contact(self : SecurityTxt) -> String? {
  for entry in self.entries {
    match entry.field {
      Contact(value) => return Some(value)
      _ => ()
    }
  }
  None
}

///|
/// Raw `Expires` value, when present.
pub fn SecurityTxt::expires_value(self : SecurityTxt) -> String? {
  for entry in self.entries {
    match entry.field {
      Expires(value) => return Some(value)
      _ => ()
    }
  }
  None
}

///|
/// Parsed `Expires` as a `DateTime`; fails SecurityTxtError when absent or malformed.
pub fn SecurityTxt::expires(
  self : SecurityTxt,
) -> Result[DateTime, SecurityTxtError] {
  for entry in self.entries {
    match entry.field {
      Expires(value) =>
        match parse_rfc3339(value) {
          Ok(dt) => return Ok(dt)
          Err(err) =>
            return Err(
              security_txt_error(
                err.stage(),
                err.kind(),
                entry.line,
                entry.byte_offset + 1 + err.column(),
                entry.byte_offset + 1 + err.byte_offset(),
                err.message(),
              ),
            )
        }
      _ => ()
    }
  }
  Err(
    security_txt_error(
      Validation,
      MissingExpires,
      0,
      0,
      -1,
      "document has no Expires field",
    ),
  )
}

///|
/// Raw `Canonical` value, when present.
pub fn SecurityTxt::canonical(self : SecurityTxt) -> String? {
  for entry in self.entries {
    match entry.field {
      Canonical(value) => return Some(value)
      _ => ()
    }
  }
  None
}

///|
/// All `Canonical` values in original order.
pub fn SecurityTxt::canonicals(self : SecurityTxt) -> Array[String] {
  let out : Array[String] = []
  for entry in self.entries {
    match entry.field {
      Canonical(value) => out.push(value)
      _ => ()
    }
  }
  out
}

///|
/// Raw `Encryption` value, when present.
pub fn SecurityTxt::encryption(self : SecurityTxt) -> String? {
  for entry in self.entries {
    match entry.field {
      Encryption(value) => return Some(value)
      _ => ()
    }
  }
  None
}

///|
/// All `Acknowledgments` values in original order.
pub fn SecurityTxt::acknowledgments(self : SecurityTxt) -> Array[String] {
  let out : Array[String] = []
  for entry in self.entries {
    match entry.field {
      Acknowledgments(value) => out.push(value)
      _ => ()
    }
  }
  out
}

///|
/// Raw `Policy` value, when present.
pub fn SecurityTxt::policy(self : SecurityTxt) -> String? {
  for entry in self.entries {
    match entry.field {
      Policy(value) => return Some(value)
      _ => ()
    }
  }
  None
}

///|
/// Raw `Hiring` value, when present.
pub fn SecurityTxt::hiring(self : SecurityTxt) -> String? {
  for entry in self.entries {
    match entry.field {
      Hiring(value) => return Some(value)
      _ => ()
    }
  }
  None
}

///|
/// Raw `Preferred-Languages` value, when present.
pub fn SecurityTxt::preferred_languages_value(self : SecurityTxt) -> String? {
  for entry in self.entries {
    match entry.field {
      PreferredLanguages(value) => return Some(value)
      _ => ()
    }
  }
  None
}

///|
/// `Preferred-Languages` split into trimmed tags, in listed order.
pub fn SecurityTxt::preferred_languages(self : SecurityTxt) -> Array[String] {
  match self.preferred_languages_value() {
    None => []
    Some(value) => split_preferred_languages(value)
  }
}

///|
/// All extension fields in original order.
pub fn SecurityTxt::extensions(self : SecurityTxt) -> Array[ExtensionField] {
  let out : Array[ExtensionField] = []
  for entry in self.entries {
    match entry.field {
      Extension(name, value) => out.push(extension_field(name, value))
      _ => ()
    }
  }
  out
}

///|
/// Comment text lines (without the leading `#`), in original order.
pub fn SecurityTxt::comments(self : SecurityTxt) -> Array[String] {
  self.comments
}

///|
/// True when the input carried an OpenPGP signed envelope.
pub fn SecurityTxt::is_signed(self : SecurityTxt) -> Bool {
  self.signature == SignedUnverified
}

///|
/// Signature state of the document.
pub fn SecurityTxt::signature_state(self : SecurityTxt) -> SignatureState {
  self.signature
}

///|
/// OpenPGP armor headers seen in the signed envelope (e.g. `Hash: SHA256`).
pub fn SecurityTxt::armor_headers(self : SecurityTxt) -> Array[String] {
  self.armor_headers
}

///|
/// Number of physical lines in the original input.
pub fn SecurityTxt::line_count(self : SecurityTxt) -> Int {
  self.line_count
}

///|
/// Size of the original input in bytes.
pub fn SecurityTxt::byte_count(self : SecurityTxt) -> Int {
  self.byte_count
}

///|
/// Total number of fields, standard and extension.
pub fn SecurityTxt::field_count(self : SecurityTxt) -> Int {
  self.entries.length()
}

///|
/// Number of standard RFC 9116 fields.
pub fn SecurityTxt::standard_field_count(self : SecurityTxt) -> Int {
  let mut count = 0
  for entry in self.entries {
    if entry.field.is_standard() {
      count += 1
    }
  }
  count
}

///|
/// Number of extension fields.
pub fn SecurityTxt::extension_field_count(self : SecurityTxt) -> Int {
  self.field_count() - self.standard_field_count()
}

///|
/// Canonical field name for this field; for extensions, the name as written.
pub fn SecurityField::name(self : SecurityField) -> String {
  match self {
    Contact(_) => "Contact"
    Expires(_) => "Expires"
    Canonical(_) => "Canonical"
    Encryption(_) => "Encryption"
    Acknowledgments(_) => "Acknowledgments"
    Policy(_) => "Policy"
    Hiring(_) => "Hiring"
    PreferredLanguages(_) => "Preferred-Languages"
    Extension(name, _) => name
  }
}

///|
/// Raw value string for this field.
pub fn SecurityField::value(self : SecurityField) -> String {
  match self {
    Contact(v) | Expires(v) | Canonical(v) | Encryption(v) => v
    Acknowledgments(v) | Policy(v) | Hiring(v) | PreferredLanguages(v) => v
    Extension(_, v) => v
  }
}

///|
/// True for the nine standard RFC 9116 fields.
pub fn SecurityField::is_standard(self : SecurityField) -> Bool {
  match self {
    Extension(_, _) => false
    _ => true
  }
}

///|
/// True for fields that MUST NOT appear more than once per RFC 9116.
pub fn SecurityField::is_singleton(self : SecurityField) -> Bool {
  match self {
    Expires(_) | PreferredLanguages(_) => true
    _ => false
  }
}

///|
/// Library version string, used by the CLI's `--version`.
pub fn library_version() -> String {
  "0.1.0"
}
