// Example: freshness checks with an explicit `now` timestamp. The library takes `now` as a parameter.

///|
fn main {
  match @lib.parse_rfc3339("2026-08-13T00:00:00Z") {
    Ok(now) => {
      let samples = [
        "2027-01-01T00:00:00Z", "2026-08-20T00:00:00Z", // far in the future; expires within 30 days
         "2026-08-12T00:00:00Z", // already expired
      ]
      for expires_text in samples {
        match @lib.parse_rfc3339(expires_text) {
          Ok(expires) => {
            let remaining = @lib.time_until_expiry(expires, now)
            let state = if @lib.is_expired(expires, now) {
              "expired"
            } else if remaining <= @lib.EXPIRES_SOON_SECONDS {
              "expires soon"
            } else {
              "fresh"
            }
            println(
              "\{expires.format_rfc3339()} at \{now.format_rfc3339()}: \{state} (\{remaining} s)",
            )
          }
          Err(err) => println("bad expiry: \{err.message()}")
        }
      }
    }
    Err(err) => println("bad now: \{err.message()}")
  }
}
