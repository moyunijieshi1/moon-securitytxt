// Lightweight advisory audit for security.txt documents.
// Findings are advisory, not validation failures: a document without `Policy` or `Canonical` may be
// perfectly legal RFC 9116. Run the validator first for hard constraints; the audit layer then
// describes risks and suggestions.

///|
/// The kinds of advisory findings the audit layer can produce.
pub(all) enum AuditFindingKind {
  Expired
  ExpiresSoon
  NoPolicy
  NoCanonical
  CanonicalMismatch
  InsecureWebUri
  DuplicateSingletonField
  UnknownExtension
  NoPreferredLanguages
  InvalidContext
  Unsigned
} derive(Eq, Debug)

///|
/// Severity of a finding. `Warning` flags actively risky states.
pub(all) enum AuditSeverity {
  Info
  Warning
} derive(Eq, Debug)

///|
/// One advisory finding with an optional source line (0 when n/a).
pub struct AuditFinding {
  kind : AuditFindingKind
  severity : AuditSeverity
  message : String
  line : Int
} derive(Eq, Debug)

///|
/// Seconds before expiry that count as `ExpiresSoon` (project-defined).
pub const EXPIRES_SOON_SECONDS : Int64 = 30L * 24L * 60L * 60L

///|
/// Construct a finding.
pub fn audit_finding(
  kind : AuditFindingKind,
  severity : AuditSeverity,
  message : String,
  line : Int,
) -> AuditFinding {
  { kind, severity, message, line }
}

///|
/// Finding kind.
pub fn AuditFinding::kind(self : AuditFinding) -> AuditFindingKind {
  self.kind
}

///|
/// Finding severity.
pub fn AuditFinding::severity(self : AuditFinding) -> AuditSeverity {
  self.severity
}

///|
/// Human-readable description.
pub fn AuditFinding::message(self : AuditFinding) -> String {
  self.message
}

///|
/// Source line (0 when the finding is document-wide).
pub fn AuditFinding::line(self : AuditFinding) -> Int {
  self.line
}

///|
/// Stable kebab-case label, useful for CLI output.
pub fn AuditFindingKind::label(self : AuditFindingKind) -> String {
  match self {
    Expired => "expired"
    ExpiresSoon => "expires-soon"
    NoPolicy => "no-policy"
    NoCanonical => "no-canonical"
    CanonicalMismatch => "canonical-mismatch"
    InsecureWebUri => "insecure-web-uri"
    DuplicateSingletonField => "duplicate-singleton-field"
    UnknownExtension => "unknown-extension"
    NoPreferredLanguages => "no-preferred-languages"
    InvalidContext => "invalid-context"
    Unsigned => "unsigned"
  }
}

///|
/// Stable severity label.
pub fn AuditSeverity::label(self : AuditSeverity) -> String {
  match self {
    Info => "info"
    Warning => "warning"
  }
}

///|
/// Audit a parsed document against `now` and a retrieval context; findings are deterministic.
pub fn audit(
  document : SecurityTxt,
  now : DateTime,
  context : SecurityTxtContext,
) -> Array[AuditFinding] {
  let findings : Array[AuditFinding] = []
  fn push(
    kind : AuditFindingKind,
    severity : AuditSeverity,
    message : String,
    line : Int,
  ) {
    findings.push(audit_finding(kind, severity, message, line))
  }
  match document.expires() {
    Ok(expires) => {
      let remaining = time_until_expiry(expires, now)
      if remaining < 0L {
        push(
          Expired,
          Warning,
          "document has expired at \{expires.format_rfc3339()}",
          0,
        )
      } else if remaining <= EXPIRES_SOON_SECONDS {
        push(
          ExpiresSoon,
          Warning,
          "document expires within 30 days (\{remaining} seconds remaining)",
          0,
        )
      }
    }
    _ => ()
  }
  match document.policy() {
    None =>
      push(
        NoPolicy,
        Info,
        "no Policy field: RFC 9116 recommends linking a vulnerability disclosure policy",
        0,
      )
    _ => ()
  }
  match document.canonical() {
    None =>
      push(
        NoCanonical,
        Info,
        "no Canonical field: a canonical URI helps detect tampering or forks",
        0,
      )
    _ => ()
  }
  match document.preferred_languages_value() {
    None =>
      push(
        NoPreferredLanguages,
        Info,
        "no Preferred-Languages field: content language is unspecified",
        0,
      )
    _ => ()
  }
  if !document.canonicals().is_empty() {
    match validate_retrieval_context(document, context) {
      Ok(_) => ()
      Err(err) =>
        push(
          CanonicalMismatch,
          if context.retrieval_uri is Some(_) {
            Warning
          } else {
            Info
          },
          err.message(),
          0,
        )
    }
  }
  match validate_context(context) {
    Ok(_) => ()
    Err(err) =>
      push(
        InvalidContext,
        Warning,
        "retrieval context is not RFC 9116 compliant: \{err.message()}",
        0,
      )
  }
  let seen_extensions : Array[String] = []
  let singleton_counts : Map[String, Int] = Map([])
  for entry in document.entries() {
    match entry.field {
      Contact(value)
      | Canonical(value)
      | Encryption(value)
      | Acknowledgments(value)
      | Policy(value)
      | Hiring(value) =>
        match uri_scheme(value) {
          Some("http") =>
            push(
              InsecureWebUri,
              Warning,
              "\{entry.field.name()} uses http://; prefer https://",
              entry.line,
            )
          _ => ()
        }
      Extension(name, _) =>
        if !seen_extensions.contains(name) {
          seen_extensions.push(name)
          push(
            UnknownExtension,
            Info,
            "unknown extension field '\{name}' (RFC 9116 allows extensions; consumers may ignore it)",
            entry.line,
          )
        }
      Expires(_) | PreferredLanguages(_) => ()
    }
    if entry.field.is_singleton() {
      let name = entry.field.name()
      let count = match singleton_counts.get(name) {
        Some(n) => n
        None => 0
      }
      singleton_counts.set(name, count + 1)
    }
  }
  for name, count in singleton_counts {
    if count > 1 {
      push(
        DuplicateSingletonField,
        Warning,
        "singleton field '\{name}' appears \{count} times",
        0,
      )
    }
  }
  match document.signature_state() {
    Unsigned =>
      push(
        Unsigned,
        Info,
        "document is not digitally signed: authenticity cannot be checked by recipients",
        0,
      )
    SignedUnverified => ()
  }
  findings
}
