// Structured errors for every security.txt processing stage. Parser reports
// syntax problems, validator reports RFC 9116 field violations, audit reports
// advisories. Errors carry stage, kind, 1-based line/column, 0-based byte
// offset so callers can locate problems precisely.

///|
/// The processing stage an error was produced in.
pub(all) enum SecurityTxtErrorStage {
  Input
  Line
  FieldName
  FieldValue
  Uri
  DateTime
  Language
  SignatureEnvelope
  Validation
  Limit
} derive(Eq, Debug)

///|
/// The concrete error kind, one distinct kind per violation.
pub(all) enum SecurityTxtErrorKind {
  InvalidLine
  MissingColon
  EmptyFieldName
  EmptyFieldValue
  InvalidUtf8
  InvalidUri
  InvalidScheme
  InvalidDateTime
  InvalidLanguage
  DuplicateExpires
  DuplicatePreferredLanguages
  DuplicateField
  MissingContact
  MissingExpires
  ContextMismatch
  InvalidContext
  LimitExceeded
  InvalidSignatureEnvelope
} derive(Eq, Debug)

///|
/// A structured security.txt error: stage, kind and exact position.
pub(all) suberror SecurityTxtError {
  SecurityTxtError(
    SecurityTxtErrorStage,
    SecurityTxtErrorKind,
    Int,
    Int,
    Int,
    String
  )
}

///|
fn max_context_bytes() -> Int {
  200
}

///|
fn bound_context(context : String) -> String {
  if context.length() <= max_context_bytes() {
    context
  } else {
    "\{slice(context, 0, max_context_bytes())}..."
  }
}

///|
/// Extract the package suberror from a caught `Error`.
fn unwrap_security_txt_error(e : Error) -> SecurityTxtError {
  match e {
    SecurityTxtError(stage, kind, line, column, offset, message) =>
      SecurityTxtError(stage, kind, line, column, offset, message)
    _ => abort("internal error: unexpected non-SecurityTxtError")
  }
}

///|
/// Construct a security.txt error; line/column 1-based, byte_offset 0-based.
pub fn security_txt_error(
  stage : SecurityTxtErrorStage,
  kind : SecurityTxtErrorKind,
  line : Int,
  column : Int,
  byte_offset : Int,
  message : String,
) -> SecurityTxtError {
  SecurityTxtError(
    stage,
    kind,
    line,
    column,
    byte_offset,
    bound_context(message),
  )
}

///|
/// The processing stage of this error.
pub fn SecurityTxtError::stage(
  self : SecurityTxtError,
) -> SecurityTxtErrorStage {
  match self {
    SecurityTxtError(stage, _, _, _, _, _) => stage
  }
}

///|
/// The kind of this error.
pub fn SecurityTxtError::kind(self : SecurityTxtError) -> SecurityTxtErrorKind {
  match self {
    SecurityTxtError(_, kind, _, _, _, _) => kind
  }
}

///|
/// 1-based line number, 0 when unknown.
pub fn SecurityTxtError::line(self : SecurityTxtError) -> Int {
  match self {
    SecurityTxtError(_, _, line, _, _, _) => line
  }
}

///|
/// 1-based column number, 0 when unknown.
pub fn SecurityTxtError::column(self : SecurityTxtError) -> Int {
  match self {
    SecurityTxtError(_, _, _, column, _, _) => column
  }
}

///|
/// 0-based byte offset into the raw input, -1 when unknown.
pub fn SecurityTxtError::byte_offset(self : SecurityTxtError) -> Int {
  match self {
    SecurityTxtError(_, _, _, _, offset, _) => offset
  }
}

///|
/// Human-readable description of the violation.
pub fn SecurityTxtError::message(self : SecurityTxtError) -> String {
  match self {
    SecurityTxtError(_, _, _, _, _, message) => message
  }
}

///|
/// Render the error as a single readable line.
pub fn SecurityTxtError::to_string(self : SecurityTxtError) -> String {
  if self.line() > 0 {
    "\{self.stage().to_string()}::\{self.kind().to_string()} at byte \{self.byte_offset()}, line \{self.line()}, column \{self.column()}: \{self.message()}"
  } else {
    "\{self.stage().to_string()}::\{self.kind().to_string()}: \{self.message()}"
  }
}

///|
/// Render the error stage name.
pub fn SecurityTxtErrorStage::to_string(self : SecurityTxtErrorStage) -> String {
  match self {
    Input => "Input"
    Line => "Line"
    FieldName => "FieldName"
    FieldValue => "FieldValue"
    Uri => "Uri"
    DateTime => "DateTime"
    Language => "Language"
    SignatureEnvelope => "SignatureEnvelope"
    Validation => "Validation"
    Limit => "Limit"
  }
}

///|
/// Render the error kind name.
pub fn SecurityTxtErrorKind::to_string(self : SecurityTxtErrorKind) -> String {
  match self {
    InvalidLine => "InvalidLine"
    MissingColon => "MissingColon"
    EmptyFieldName => "EmptyFieldName"
    EmptyFieldValue => "EmptyFieldValue"
    InvalidUtf8 => "InvalidUtf8"
    InvalidUri => "InvalidUri"
    InvalidScheme => "InvalidScheme"
    InvalidDateTime => "InvalidDateTime"
    InvalidLanguage => "InvalidLanguage"
    DuplicateExpires => "DuplicateExpires"
    DuplicatePreferredLanguages => "DuplicatePreferredLanguages"
    DuplicateField => "DuplicateField"
    MissingContact => "MissingContact"
    MissingExpires => "MissingExpires"
    ContextMismatch => "ContextMismatch"
    InvalidContext => "InvalidContext"
    LimitExceeded => "LimitExceeded"
    InvalidSignatureEnvelope => "InvalidSignatureEnvelope"
  }
}
