// securitytxt-tool entry point. All input is passed with --text for target portability: the CLI never
// opens files or touches the network, matching the library's scope. Successful commands print JSON on
// stdout; `generate` prints the document text. Errors print {"ok":false,"error":{...}}.

///|
fn main {
  run_cli(@env.args())
}

///|
fn run_cli(args : Array[String]) -> Unit {
  let (cmd, rest) = split_command(args)
  let opts = parse_options(rest)
  if opts.unknown.length() > 0 {
    println(
      "{\"ok\":false,\"error\":{\"kind\":\"UnknownOption\",\"option\":\{q(opts.unknown)}}}",
    )
    return
  }
  if opts.help || cmd == "help" {
    print_usage()
    return
  }
  if cmd == "version" {
    println(
      "securitytxt-tool \{@lib.library_version()} (moyunijieshi1/moon-securitytxt)",
    )
    return
  }
  match cmd {
    "parse" => cmd_parse(opts)
    "validate" => cmd_validate(opts)
    "fresh" => cmd_fresh(opts)
    "generate" => cmd_generate(opts)
    "audit" => cmd_audit(opts)
    "stats" => cmd_stats(opts)
    _ =>
      println(
        "{\"ok\":false,\"error\":{\"kind\":\"UnknownCommand\",\"command\":\{q(cmd)}}}",
      )
  }
}

///|
fn print_usage() -> Unit {
  println("securitytxt-tool 0.1.0 — RFC 9116 security.txt toolkit")
  println(
    "usage: securitytxt-tool <parse|validate|fresh|generate|audit|stats> --text <document>",
  )
  println(
    "shared: --limits <default|strict|permissive> --now <rfc3339> --retrieval-uri <uri> --content-type <type>",
  )
  println(
    "generate: --contact <uri> --expires <rfc3339> --canonical <uri> --encryption <uri>",
  )
  println(
    "generate: --acknowledgments <uri> --policy <uri> --hiring <uri> --preferred-languages <tags>",
  )
  println("generate: --extension <Name:value> --comment <text>")
  println(
    "notes: fresh and audit require --now; generate prints the document text; repeatable options accumulate",
  )
}
