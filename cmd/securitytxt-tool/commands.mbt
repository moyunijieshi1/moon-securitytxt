// Command handlers for securitytxt-tool.

///|
fn cmd_parse(o : CliOptions) -> Unit {
  match parse_or_print(o) {
    Some(document) => println(parse_json(document))
    None => ()
  }
}

///|
fn cmd_validate(o : CliOptions) -> Unit {
  match parse_or_print(o) {
    Some(document) => println(validate_with_context_json(document, o))
    None => ()
  }
}

///|
/// Freshness check: how far the document's Expires is from --now.
fn cmd_fresh(o : CliOptions) -> Unit {
  match resolve_now(o) {
    Err(message) => println(message)
    Ok(None) => println(missing_option_json("fresh requires --now <rfc3339>"))
    Ok(Some(now)) =>
      match parse_or_print(o) {
        Some(document) => println(fresh_json(document, now))
        None => ()
      }
  }
}

///|
/// Generate a validated document; prints the document text on stdout.
fn cmd_generate(o : CliOptions) -> Unit {
  let mut builder = @lib.new_builder()
  for contact in o.contacts {
    builder = builder.contact(contact)
  }
  for uri in o.acknowledgments {
    builder = builder.acknowledgments(uri)
  }
  for comment in o.comments {
    builder = builder.comment(comment)
  }
  for ext in o.extensions {
    match ext.find(":") {
      None => {
        println(
          missing_option_json("--extension expects <Name:value>, got '\{ext}'"),
        )
        return
      }
      Some(idx) =>
        builder = builder.extension(
          ext[0:idx].to_owned(),
          ext[idx + 1:ext.length()].to_owned(),
        )
    }
  }
  if o.expires.length() > 0 {
    match @lib.parse_rfc3339(o.expires) {
      Ok(dt) => builder = builder.expires(dt)
      Err(err) => {
        println(error_json(err))
        return
      }
    }
  }
  if o.canonical.length() > 0 {
    builder = builder.canonical(o.canonical)
  }
  if o.encryption.length() > 0 {
    builder = builder.encryption(o.encryption)
  }
  if o.policy.length() > 0 {
    builder = builder.policy(o.policy)
  }
  if o.hiring.length() > 0 {
    builder = builder.hiring(o.hiring)
  }
  if o.preferred_languages.length() > 0 {
    let tags : Array[String] = []
    for tag in o.preferred_languages.split(",") {
      tags.push(tag.trim().to_owned())
    }
    builder = builder.preferred_languages(tags)
  }
  match builder.build() {
    Ok(document) => println(@lib.serialize_security_txt(document))
    Err(err) => println(error_json(err))
  }
}

///|
fn cmd_audit(o : CliOptions) -> Unit {
  match resolve_now(o) {
    Err(message) => println(message)
    Ok(None) => println(missing_option_json("audit requires --now <rfc3339>"))
    Ok(Some(now)) =>
      match parse_or_print(o) {
        Some(document) =>
          println(audit_json(@lib.audit(document, now, resolve_context(o))))
        None => ()
      }
  }
}

///|
fn cmd_stats(o : CliOptions) -> Unit {
  match parse_or_print(o) {
    Some(document) => println(stats_json(document))
    None => ()
  }
}
