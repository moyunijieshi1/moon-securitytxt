// Retrieval-context validation. RFC 9116 Section 3 fixes the security.txt location at
// /.well-known/security.txt over HTTPS; this module validates the caller-provided context
// (retrieval URI, content type) and compares it with the document's Canonical field. The
// library never fetches anything — the caller supplies the strings it observed.

///|
/// How a document was retrieved; both fields optional — absent values skip checks.
pub struct SecurityTxtContext {
  retrieval_uri : String?
  content_type : String?
} derive(Eq, Debug)

///|
/// An empty context: no retrieval information available.
pub fn empty_context() -> SecurityTxtContext {
  { retrieval_uri: None, content_type: None }
}

///|
/// Build a retrieval context.
pub fn security_txt_context(
  retrieval_uri : String?,
  content_type : String?,
) -> SecurityTxtContext {
  { retrieval_uri, content_type }
}

///|
/// The retrieval URI as provided by the caller.
pub fn SecurityTxtContext::retrieval_uri(self : SecurityTxtContext) -> String? {
  self.retrieval_uri
}

///|
/// The Content-Type header value as provided by the caller.
pub fn SecurityTxtContext::content_type(self : SecurityTxtContext) -> String? {
  self.content_type
}

///|
fn context_error(
  kind : SecurityTxtErrorKind,
  message : String,
) -> SecurityTxtError {
  security_txt_error(Validation, kind, 0, 0, -1, message)
}

///|
fn check_retrieval_uri(uri : String) -> Result[Unit, SecurityTxtError] {
  match uri_scheme(uri) {
    None =>
      return Err(context_error(InvalidContext, "retrieval URI has no scheme"))
    Some(scheme) =>
      if scheme != "https" {
        return Err(
          context_error(
            InvalidContext,
            "retrieval URI scheme is '\{scheme}'; RFC 9116 requires https",
          ),
        )
      }
  }
  // Strip query and fragment, then require the well-known path suffix.
  let mut path_end = uri.length()
  let mut i = 0
  for c in uri {
    if (c == '?' || c == '#') && i > 0 {
      path_end = i
      break
    }
    i += 1
  }
  let path = slice(uri, 0, path_end)
  if !path.has_suffix("/.well-known/security.txt") {
    return Err(
      context_error(
        InvalidContext,
        "retrieval URI path must end with /.well-known/security.txt",
      ),
    )
  }
  Ok(())
}

///|
fn check_content_type(content_type : String) -> Result[Unit, SecurityTxtError] {
  let parts : Array[String] = []
  for part in content_type.split(";") {
    parts.push(part.trim().to_owned())
  }
  if parts.length() == 0 {
    return Err(context_error(InvalidContext, "content type is empty"))
  }
  let media_type = ascii_lower(parts[0])
  if media_type != "text/plain" {
    return Err(
      context_error(
        InvalidContext,
        "content type must be text/plain, found '\{media_type}'",
      ),
    )
  }
  let mut i = 1
  while i < parts.length() {
    let param = parts[i]
    if ascii_lower(param).has_prefix("charset=") {
      let charset = slice(param, "charset=".length(), param.length())
      if ascii_lower(charset) != "utf-8" {
        return Err(
          context_error(
            InvalidContext,
            "charset must be utf-8, found '\{charset}'",
          ),
        )
      }
    }
    i += 1
  }
  Ok(())
}

///|
/// Validate the retrieval context: HTTPS, well-known path, text/plain; charset=utf-8.
pub fn validate_context(
  context : SecurityTxtContext,
) -> Result[Unit, SecurityTxtError] {
  match context.retrieval_uri {
    Some(uri) =>
      match check_retrieval_uri(uri) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    None => ()
  }
  match context.content_type {
    Some(ct) =>
      match check_content_type(ct) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    None => ()
  }
  Ok(())
}

///|
/// Compare the retrieval URI with all Canonical fields: one must match exactly.
pub fn validate_retrieval_context(
  document : SecurityTxt,
  context : SecurityTxtContext,
) -> Result[Unit, SecurityTxtError] {
  let canonicals = document.canonicals()
  if canonicals.is_empty() {
    return Ok(())
  }
  match context.retrieval_uri {
    None =>
      Err(
        context_error(
          ContextMismatch,
          "document declares Canonical but no retrieval URI was provided",
        ),
      )
    Some(uri) => {
      for canonical in canonicals {
        if uri == canonical {
          return Ok(())
        }
      }
      Err(
        context_error(
          ContextMismatch,
          "retrieval URI '\{uri}' is not listed by any Canonical field",
        ),
      )
    }
  }
}
