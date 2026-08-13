// JSON output helpers for securitytxt-tool. A small local JSON escaper keeps the CLI self-contained:
// the library has no output-formatting concerns.

///|
/// Quote a string for JSON, escaping the required characters.
fn q(s : String) -> String {
  "\"" + json_escape(s) + "\""
}

///|
fn json_escape(s : String) -> String {
  let sb = StringBuilder::new(size_hint=s.length() + 8)
  for c in s {
    match c {
      '"' => sb.write_string("\\\"")
      '\\' => sb.write_string("\\\\")
      '\n' => sb.write_string("\\n")
      '\r' => sb.write_string("\\r")
      '\t' => sb.write_string("\\t")
      c =>
        if c.to_int() < 0x20 {
          sb.write_string("\\u")
          sb.write_string(hex4(c.to_int()))
        } else {
          sb.write_char(c)
        }
    }
  }
  sb.to_string()
}

///|
fn hex4(n : Int) -> String {
  let digits = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  ]
  let out = StringBuilder::new(size_hint=4)
  out.write_char(digits[n / 4096 % 16])
  out.write_char(digits[n / 256 % 16])
  out.write_char(digits[n / 16 % 16])
  out.write_char(digits[n % 16])
  out.to_string()
}

///|
fn bool_json(v : Bool) -> String {
  if v {
    "true"
  } else {
    "false"
  }
}

///|
/// Structured error as JSON (stage, kind, line, column, offset, message).
fn error_json(err : @lib.SecurityTxtError) -> String {
  "{\"ok\":false,\"error\":{\"stage\":\{q(err.stage().to_string())},\"kind\":\{q(err.kind().to_string())}," +
  "\"line\":\{err.line()},\"column\":\{err.column()}," +
  "\"offset\":\{err.byte_offset()},\"message\":\{q(err.message())}}}"
}

///|
fn missing_option_json(message : String) -> String {
  "{\"ok\":false,\"error\":{\"kind\":\"MissingOption\",\"message\":\{q(message)}}}"
}

///|
/// Parse a document, printing the error JSON on failure.
fn parse_or_print(o : CliOptions) -> @lib.SecurityTxt? {
  match
    @lib.parse_security_txt_with_limits(input_text(o), resolve_limits(o.limits)) {
    Ok(document) => Some(document)
    Err(err) => {
      println(error_json(err))
      None
    }
  }
}

///|
fn parse_json(document : @lib.SecurityTxt) -> String {
  let preferred = match document.preferred_contact() {
    Some(uri) => q(uri)
    None => "null"
  }
  "{\"ok\":true,\"fields\":\{document.field_count()},\"standard_fields\":\{document.standard_field_count()}," +
  "\"extension_fields\":\{document.extension_field_count()},\"contacts\":\{document.contacts().length()}," +
  "\"comments\":\{document.comments().length()},\"signed\":\{bool_json(document.is_signed())}," +
  "\"lines\":\{document.line_count()},\"bytes\":\{document.byte_count()},\"preferred_contact\":\{preferred}}"
}

///|
/// All validation errors as a JSON array fragment.
fn errors_json(errors : Array[@lib.SecurityTxtError]) -> String {
  let sb = StringBuilder::new(size_hint=errors.length() * 80)
  sb.write_char('[')
  let mut i = 0
  while i < errors.length() {
    if i > 0 {
      sb.write_char(',')
    }
    sb.write_string(
      "{\"stage\":\{q(errors[i].stage().to_string())},\"kind\":\{q(errors[i].kind().to_string())}," +
      "\"line\":\{errors[i].line()},\"column\":\{errors[i].column()},\"offset\":\{errors[i].byte_offset()}," +
      "\"message\":\{q(errors[i].message())}}",
    )
    i += 1
  }
  sb.write_char(']')
  sb.to_string()
}

///|
/// Validate document semantics and any retrieval context supplied on the CLI.
fn validate_with_context_json(
  document : @lib.SecurityTxt,
  o : CliOptions,
) -> String {
  let errors = @lib.validate_all(document)
  let context = resolve_context(o)
  match @lib.validate_context(context) {
    Err(err) => errors.push(err)
    Ok(_) =>
      if o.retrieval_uri_set {
        match @lib.validate_retrieval_context(document, context) {
          Err(err) => errors.push(err)
          Ok(_) => ()
        }
      }
  }
  "{\"ok\":true,\"valid\":\{bool_json(errors.length() == 0)},\"errors\":\{errors_json(errors)}}"
}

///|
fn fresh_json(document : @lib.SecurityTxt, now : @lib.DateTime) -> String {
  match document.expires() {
    Ok(expires) => {
      let remaining = @lib.time_until_expiry(expires, now)
      let expires_soon = remaining >= 0L &&
        remaining <= @lib.EXPIRES_SOON_SECONDS
      "{\"ok\":true,\"now\":\{q(now.format_rfc3339())},\"expires\":\{q(expires.format_rfc3339())}," +
      "\"expired\":\{bool_json(@lib.is_expired(expires, now))},\"seconds_until_expiry\":\{remaining}," +
      "\"expires_within_30_days\":\{bool_json(expires_soon)}}"
    }
    Err(err) => error_json(err)
  }
}

///|
fn audit_json(findings : Array[@lib.AuditFinding]) -> String {
  let sb = StringBuilder::new(size_hint=findings.length() * 100)
  sb.write_string("{\"ok\":true,\"findings\":[")
  let mut i = 0
  while i < findings.length() {
    if i > 0 {
      sb.write_char(',')
    }
    sb.write_string("{\"severity\":")
    sb.write_string(q(findings[i].severity().label()))
    sb.write_string(",\"kind\":")
    sb.write_string(q(findings[i].kind().label()))
    sb.write_string(",\"line\":")
    sb.write_string("\{findings[i].line()}")
    sb.write_string(",\"message\":")
    sb.write_string(q(findings[i].message()))
    sb.write_char('}')
    i += 1
  }
  sb.write_string("]}")
  sb.to_string()
}

///|
fn stats_json(document : @lib.SecurityTxt) -> String {
  let present = fn(field_name : String) -> Bool {
    let mut found = false
    for field in document.fields() {
      if field.name() == field_name {
        found = true
      }
    }
    found
  }
  "{\"ok\":true,\"fields\":\{document.field_count()},\"standard_fields\":\{document.standard_field_count()}," +
  "\"extension_fields\":\{document.extension_field_count()},\"contacts\":\{document.contacts().length()}," +
  "\"acknowledgments\":\{document.acknowledgments().length()},\"comments\":\{document.comments().length()}," +
  "\"lines\":\{document.line_count()},\"bytes\":\{document.byte_count()}," +
  "\"signed\":\{bool_json(document.is_signed())},\"has_expires\":\{bool_json(present("Expires"))}," +
  "\"has_canonical\":\{bool_json(present("Canonical"))}," +
  "\"has_encryption\":\{bool_json(present("Encryption"))},\"has_policy\":\{bool_json(present("Policy"))}," +
  "\"has_hiring\":\{bool_json(present("Hiring"))}," +
  "\"has_preferred_languages\":\{bool_json(present("Preferred-Languages"))}}"
}
