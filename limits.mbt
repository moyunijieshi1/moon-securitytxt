// Defensive resource limits for untrusted security.txt input.
//
// RFC 9116 warns that malicious or misconfigured files may be excessively large; the
// defaults below are conservative project-defined choices, not protocol limits.
// See docs/limitations.md.

///|
/// Resource limits applied while parsing.
pub struct Limits {
  max_input_bytes : Int
  max_lines : Int
  max_line_bytes : Int
  max_fields : Int
  max_field_value_bytes : Int
} derive(Eq, Debug)

///|
/// Conservative defaults suitable for untrusted input.
pub fn Limits::default() -> Limits {
  {
    max_input_bytes: 32 * 1024,
    max_lines: 1000,
    max_line_bytes: 4096,
    max_fields: 1000,
    max_field_value_bytes: 2048,
  }
}

///|
/// Tighter limits for constrained or high-risk callers.
pub fn Limits::strict() -> Limits {
  {
    max_input_bytes: 16 * 1024,
    max_lines: 512,
    max_line_bytes: 1024,
    max_fields: 256,
    max_field_value_bytes: 1024,
  }
}

///|
/// Relaxed limits for controlled environments.
pub fn Limits::permissive() -> Limits {
  {
    max_input_bytes: 8 * 1024 * 1024,
    max_lines: 131072,
    max_line_bytes: 65536,
    max_fields: 32768,
    max_field_value_bytes: 65536,
  }
}

///|
/// Build custom limits. Negative values fall back to the default.
pub fn Limits::custom(
  max_input_bytes : Int,
  max_lines : Int,
  max_line_bytes : Int,
  max_fields : Int,
  max_field_value_bytes : Int,
) -> Limits {
  let d = Limits::default()
  let pick = fn(v : Int, fallback : Int) { if v > 0 { v } else { fallback } }
  {
    max_input_bytes: pick(max_input_bytes, d.max_input_bytes),
    max_lines: pick(max_lines, d.max_lines),
    max_line_bytes: pick(max_line_bytes, d.max_line_bytes),
    max_fields: pick(max_fields, d.max_fields),
    max_field_value_bytes: pick(max_field_value_bytes, d.max_field_value_bytes),
  }
}

///|
/// Maximum input size in bytes.
pub fn Limits::max_input_bytes(self : Limits) -> Int {
  self.max_input_bytes
}

///|
/// Maximum number of physical lines.
pub fn Limits::max_lines(self : Limits) -> Int {
  self.max_lines
}

///|
/// Maximum length of one physical line in bytes (excluding the line break).
pub fn Limits::max_line_bytes(self : Limits) -> Int {
  self.max_line_bytes
}

///|
/// Maximum number of field lines (standard and extension combined).
pub fn Limits::max_fields(self : Limits) -> Int {
  self.max_fields
}

///|
/// Maximum length of one field value in bytes.
pub fn Limits::max_field_value_bytes(self : Limits) -> Int {
  self.max_field_value_bytes
}
