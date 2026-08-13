// Example: validate documents and print every structured error. RFC constraints only; suggestions live in audit.

///|
fn main {
  let samples = [
    // sample 2: missing Expires; sample 3: no Contact + duplicate Expires; sample 4: invalid values
    "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n", "Contact: mailto:security@example.com\n",
    "Expires: 2027-01-01T00:00:00Z\nExpires: 2028-01-01T00:00:00Z\n", "Contact: not a uri\nExpires: next Tuesday\n",
  ]
  let mut i = 0
  while i < samples.length() {
    println("--- sample \{i + 1} ---")
    match @lib.parse_security_txt(samples[i]) {
      Ok(document) => {
        let errors = @lib.validate_all(document)
        if errors.length() == 0 {
          println("valid")
        } else {
          println("invalid (\{errors.length()} errors):")
          for err in errors {
            println("  \{err.to_string()}")
          }
        }
      }
      Err(err) => println("parse error: \{err.to_string()}")
    }
    i += 1
  }
}
