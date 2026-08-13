// OpenPGP cleartext-signature envelope detection and extraction (RFC 9116 2.3,
// RFC 4880 7). v0.1.0-dev performs NO verification: a detected envelope is
// SignedUnverified — never verified. See docs/limitations.md.

///|
/// Result of scanning an input for a signed envelope.
pub struct SignedPayload {
  armor_headers : Array[String]
  cleartext_lines : Array[String]
  cleartext_offsets : Array[Int]
}

///|
/// Armor headers from the envelope (for example `Hash: SHA256`).
pub fn SignedPayload::armor_headers(self : SignedPayload) -> Array[String] {
  self.armor_headers
}

///|
/// Dash-unescaped cleartext lines.
pub fn SignedPayload::cleartext_lines(self : SignedPayload) -> Array[String] {
  self.cleartext_lines
}

///|
/// Byte offsets of the cleartext lines in the original input.
pub fn SignedPayload::cleartext_offsets(self : SignedPayload) -> Array[Int] {
  self.cleartext_offsets
}

///|
/// Strip one leading RFC 4880 dash-escape (`- ` doubling) from a cleartext line.
fn unescape_dash(line : String) -> String {
  if line.has_prefix("- ") {
    slice(line, 2, line.length())
  } else {
    line
  }
}

///|
fn signature_error(
  line : Int,
  offset : Int,
  message : String,
) -> SecurityTxtError {
  security_txt_error(
    SignatureEnvelope,
    InvalidSignatureEnvelope,
    line,
    1,
    offset,
    message,
  )
}

///|
/// Split a signed envelope: Ok(None)=unsigned, Ok(Some(payload))=complete, Err=malformed.
pub fn split_signed_envelope(
  lines : Array[String],
  offsets : Array[Int],
) -> Result[SignedPayload?, SecurityTxtError] {
  if lines.length() == 0 {
    return Ok(None)
  }
  if lines[0] != "-----BEGIN PGP SIGNED MESSAGE-----" {
    return Ok(None)
  }
  // Armor headers end at the first blank line, which MUST be present.
  let mut i = 1
  let headers : Array[String] = []
  let mut seen_blank = false
  while i < lines.length() && !seen_blank {
    if lines[i].length() == 0 {
      seen_blank = true
    } else {
      headers.push(lines[i])
    }
    i += 1
  }
  if !seen_blank {
    return Err(
      signature_error(
        i + 1,
        offsets[lines.length() - 1],
        "missing blank line after armor headers",
      ),
    )
  }
  // Cleartext until the signature marker; signers dash-escape any raw line equal to the marker.
  let cleartext : Array[String] = []
  let clear_offsets : Array[Int] = []
  let mut found_signature = false
  while i < lines.length() && lines[i] != "-----BEGIN PGP SIGNATURE-----" {
    cleartext.push(unescape_dash(lines[i]))
    clear_offsets.push(offsets[i])
    i += 1
  }
  if i < lines.length() {
    found_signature = true
    i += 1
  }
  if !found_signature {
    return Err(
      signature_error(
        i + 1,
        offsets[lines.length() - 1],
        "missing PGP BEGIN SIGNATURE marker",
      ),
    )
  }
  // Signature block until the END marker.
  let mut found_end = false
  while i < lines.length() && lines[i] != "-----END PGP SIGNATURE-----" {
    i += 1
  }
  if i < lines.length() {
    found_end = true
    i += 1
  }
  if !found_end {
    return Err(
      signature_error(
        i + 1,
        offsets[lines.length() - 1],
        "missing PGP END SIGNATURE marker",
      ),
    )
  }
  // Nothing but blank lines may follow the signature block.
  while i < lines.length() && lines[i].length() == 0 {
    i += 1
  }
  if i < lines.length() {
    return Err(
      signature_error(
        i + 1,
        offsets[i],
        "unexpected content after the signature block",
      ),
    )
  }
  Ok(
    Some({
      armor_headers: headers,
      cleartext_lines: cleartext,
      cleartext_offsets: clear_offsets,
    }),
  )
}

///|
/// Extract the cleartext body of a signed message (joined with LF). No verification.
pub fn extract_cleartext(input : String) -> Result[String?, SecurityTxtError] {
  let (lines, offsets) = split_lines_text(input)
  match split_signed_envelope(lines, offsets) {
    Ok(None) => Ok(None)
    Ok(Some(payload)) => Ok(Some(payload.cleartext_lines.join("\n")))
    Err(err) => Err(err)
  }
}
