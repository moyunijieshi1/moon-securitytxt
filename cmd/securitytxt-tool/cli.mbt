// Argument parsing for the portable securitytxt-tool CLI.

///|
/// Parsed options: single-value keeps the last occurrence; repeatable accumulate.
struct CliOptions {
  mut text : String
  mut text_set : Bool
  mut limits : String
  mut now : String
  mut retrieval_uri : String
  mut retrieval_uri_set : Bool
  mut content_type : String
  mut content_type_set : Bool
  mut expires : String
  mut canonical : String
  mut encryption : String
  mut policy : String
  mut hiring : String
  mut preferred_languages : String
  contacts : Array[String]
  acknowledgments : Array[String]
  extensions : Array[String]
  comments : Array[String]
  mut help : Bool
  positionals : Array[String]
  mut unknown : String
}

///|
fn empty_options() -> CliOptions {
  {
    text: "",
    text_set: false,
    limits: "default",
    now: "",
    retrieval_uri: "",
    retrieval_uri_set: false,
    content_type: "",
    content_type_set: false,
    expires: "",
    canonical: "",
    encryption: "",
    policy: "",
    hiring: "",
    preferred_languages: "",
    contacts: [],
    acknowledgments: [],
    extensions: [],
    comments: [],
    help: false,
    positionals: [],
    unknown: "",
  }
}

///|
fn known_command(cmd : String) -> Bool {
  cmd == "parse" ||
  cmd == "validate" ||
  cmd == "fresh" ||
  cmd == "generate" ||
  cmd == "audit" ||
  cmd == "stats" ||
  cmd == "help" ||
  cmd == "version" ||
  cmd == "--help" ||
  cmd == "--version"
}

///|
fn split_command(args : Array[String]) -> (String, Array[String]) {
  if args.is_empty() {
    return ("help", [])
  }
  let start = if known_command(args[0]) { 0 } else { 1 }
  if start >= args.length() {
    return ("help", [])
  }
  let cmd = match args[start] {
    "--help" => "help"
    "--version" => "version"
    name => name
  }
  (cmd, args[start + 1:].to_owned())
}

///|
/// Options that take a value; repeatable options land in arrays.
fn value_option(name : String) -> Bool {
  name == "--text" ||
  name == "--limits" ||
  name == "--now" ||
  name == "--retrieval-uri" ||
  name == "--content-type" ||
  name == "--expires" ||
  name == "--canonical" ||
  name == "--encryption" ||
  name == "--policy" ||
  name == "--hiring" ||
  name == "--preferred-languages" ||
  name == "--contact" ||
  name == "--acknowledgments" ||
  name == "--extension" ||
  name == "--comment"
}

///|
fn parse_options(args : Array[String]) -> CliOptions {
  let o = empty_options()
  let mut i = 0
  while i < args.length() {
    let a = args[i]
    if value_option(a) {
      let value = if i + 1 < args.length() { args[i + 1] } else { "" }
      match a {
        "--text" => {
          o.text = value
          o.text_set = true
        }
        "--limits" => o.limits = value
        "--now" => o.now = value
        "--retrieval-uri" => {
          o.retrieval_uri = value
          o.retrieval_uri_set = true
        }
        "--content-type" => {
          o.content_type = value
          o.content_type_set = true
        }
        "--expires" => o.expires = value
        "--canonical" => o.canonical = value
        "--encryption" => o.encryption = value
        "--policy" => o.policy = value
        "--hiring" => o.hiring = value
        "--preferred-languages" => o.preferred_languages = value
        "--contact" => o.contacts.push(value)
        "--acknowledgments" => o.acknowledgments.push(value)
        "--extension" => o.extensions.push(value)
        "--comment" => o.comments.push(value)
        _ => ()
      }
      i += 2
    } else if a == "--help" || a == "-h" {
      o.help = true
      i += 1
    } else if a.has_prefix("-") {
      o.unknown = a
      i += 1
    } else {
      o.positionals.push(a)
      i += 1
    }
  }
  o
}

///|
fn resolve_limits(name : String) -> @lib.Limits {
  match name {
    "strict" => @lib.Limits::strict()
    "permissive" => @lib.Limits::permissive()
    _ => @lib.Limits::default()
  }
}

///|
fn input_text(o : CliOptions) -> String {
  if o.text_set {
    o.text
  } else if o.positionals.length() > 0 {
    o.positionals[0]
  } else {
    ""
  }
}

///|
/// Parse --now; Ok(None) when absent, Err carries error JSON when not RFC 3339.
fn resolve_now(o : CliOptions) -> Result[@lib.DateTime?, String] {
  if o.now.length() == 0 {
    return Ok(None)
  }
  match @lib.parse_rfc3339(o.now) {
    Ok(dt) => Ok(Some(dt))
    Err(err) => {
      let message = "--now must be an RFC 3339 date-time: \{err.message()}"
      Err(
        "{\"ok\":false,\"error\":{\"kind\":\"InvalidNow\",\"message\":\{q(message)}}}",
      )
    }
  }
}

///|
/// Build the retrieval context from --retrieval-uri / --content-type.
fn resolve_context(o : CliOptions) -> @lib.SecurityTxtContext {
  let uri = if o.retrieval_uri_set { Some(o.retrieval_uri) } else { None }
  let ct = if o.content_type_set { Some(o.content_type) } else { None }
  @lib.security_txt_context(uri, ct)
}
