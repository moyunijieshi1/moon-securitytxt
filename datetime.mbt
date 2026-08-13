// Minimal RFC 3339 date-time handling for the security.txt `Expires` field.
// Parses/renders the RFC 3339 `date-time` production required by RFC 9116
// plus epoch arithmetic for freshness checks. No tz database, no civil math
// beyond day conversion.

///|
/// A civil date-time with a UTC offset (0 for `Z`); epoch math uses the UTC instant.
pub struct DateTime {
  year : Int
  month : Int
  day : Int
  hour : Int
  minute : Int
  second : Int
  nanos : Int64
  offset_minutes : Int
} derive(Eq, Debug)

///|
/// Maximal fractional digits accepted (nanosecond precision).
pub const RFC3339_MAX_FRACTIONAL_DIGITS : Int = 9

///|
/// Make a UTC date-time without fractional seconds. Range-checked.
pub fn make_utc(
  year : Int,
  month : Int,
  day : Int,
  hour : Int,
  minute : Int,
  second : Int,
) -> Result[DateTime, SecurityTxtError] {
  make_utc_nanos(year, month, day, hour, minute, second, 0L)
}

///|
/// Make a UTC date-time with fractional seconds as nanoseconds.
pub fn make_utc_nanos(
  year : Int,
  month : Int,
  day : Int,
  hour : Int,
  minute : Int,
  second : Int,
  nanos : Int64,
) -> Result[DateTime, SecurityTxtError] {
  if year < 0 || year > 9999 {
    return Err(invalid_datetime(0, "year must be between 0 and 9999"))
  }
  if month < 1 || month > 12 {
    return Err(invalid_datetime(0, "month must be between 1 and 12"))
  }
  if day < 1 || day > days_in_month(year, month) {
    return Err(invalid_datetime(0, "day is out of range for the given month"))
  }
  if hour < 0 || hour > 23 {
    return Err(invalid_datetime(0, "hour must be between 0 and 23"))
  }
  if minute < 0 || minute > 59 {
    return Err(invalid_datetime(0, "minute must be between 0 and 59"))
  }
  if second < 0 || second > 60 {
    return Err(invalid_datetime(0, "second must be between 0 and 60"))
  }
  if nanos < 0L || nanos >= 1_000_000_000L {
    return Err(invalid_datetime(0, "nanos must be between 0 and 999999999"))
  }
  Ok({ year, month, day, hour, minute, second, nanos, offset_minutes: 0 })
}

///|
/// Year component.
pub fn DateTime::year(self : DateTime) -> Int {
  self.year
}

///|
/// Month component (1-12).
pub fn DateTime::month(self : DateTime) -> Int {
  self.month
}

///|
/// Day component (1-31).
pub fn DateTime::day(self : DateTime) -> Int {
  self.day
}

///|
/// Hour component (0-23).
pub fn DateTime::hour(self : DateTime) -> Int {
  self.hour
}

///|
/// Minute component (0-59).
pub fn DateTime::minute(self : DateTime) -> Int {
  self.minute
}

///|
/// Second component (0-60; 60 is the leap second).
pub fn DateTime::second(self : DateTime) -> Int {
  self.second
}

///|
/// Fractional seconds in nanoseconds (0-999999999).
pub fn DateTime::nanos(self : DateTime) -> Int64 {
  self.nanos
}

///|
/// UTC offset in minutes (0 for `Z`).
pub fn DateTime::offset_minutes(self : DateTime) -> Int {
  self.offset_minutes
}

///|
/// This instant as nanoseconds since the Unix epoch (1970-01-01T00:00:00Z).
pub fn DateTime::to_epoch_nanos(self : DateTime) -> Int64 {
  let days = days_from_civil(self.year, self.month, self.day)
  let day_seconds = self.hour.to_int64() * 3600L +
    self.minute.to_int64() * 60L +
    self.second.to_int64() -
    self.offset_minutes.to_int64() * 60L
  days * 86_400L * 1_000_000_000L + day_seconds * 1_000_000_000L + self.nanos
}

///|
/// True when this instant is strictly before `other`.
pub fn DateTime::before(self : DateTime, other : DateTime) -> Bool {
  self.to_epoch_nanos() < other.to_epoch_nanos()
}

///|
/// True when this instant is strictly after `other`.
pub fn DateTime::after(self : DateTime, other : DateTime) -> Bool {
  self.to_epoch_nanos() > other.to_epoch_nanos()
}

///|
/// True when both instants coincide.
pub fn DateTime::equals(self : DateTime, other : DateTime) -> Bool {
  self.to_epoch_nanos() == other.to_epoch_nanos()
}

///|
/// True when this instant has passed relative to `now`.
pub fn is_expired(expires : DateTime, now : DateTime) -> Bool {
  expires.to_epoch_nanos() < now.to_epoch_nanos()
}

///|
/// Seconds from `now` until expiry; negative when already expired.
pub fn time_until_expiry(expires : DateTime, now : DateTime) -> Int64 {
  div_floor_i64(expires.to_epoch_nanos() - now.to_epoch_nanos(), 1_000_000_000L)
}

///|
/// Floor division for `Int64` (truncation breaks negative durations).
pub fn div_floor_i64(a : Int64, b : Int64) -> Int64 {
  let q = a / b
  if a % b != 0L && (a < 0L) != (b < 0L) {
    q - 1L
  } else {
    q
  }
}

///|
/// Slice `s[start:end]` as a String (avoids the deprecated `String::substring`).
fn slice(s : String, start : Int, end : Int) -> String {
  s[start:end].to_owned()
}

///|
/// Format as canonical RFC 3339: date, time, optional fraction, `Z` or ±HH:MM.
pub fn DateTime::format_rfc3339(self : DateTime) -> String {
  let sb = StringBuilder::new(size_hint=32)
  sb.write_string(pad4(self.year))
  sb.write_char('-')
  sb.write_string(pad2(self.month))
  sb.write_char('-')
  sb.write_string(pad2(self.day))
  sb.write_char('T')
  sb.write_string(pad2(self.hour))
  sb.write_char(':')
  sb.write_string(pad2(self.minute))
  sb.write_char(':')
  sb.write_string(pad2(self.second))
  if self.nanos != 0L {
    let frac = self.nanos.to_string()
    let mut padded = frac
    let mut _pad_i = frac.length()
    while _pad_i < RFC3339_MAX_FRACTIONAL_DIGITS {
      padded = "0\{padded}"
      _pad_i += 1
    }
    let mut trimmed = padded
    while trimmed.has_suffix("0") {
      trimmed = slice(trimmed, 0, trimmed.length() - 1)
    }
    sb.write_char('.')
    sb.write_string(trimmed)
  }
  if self.offset_minutes == 0 {
    sb.write_char('Z')
  } else {
    let sign = if self.offset_minutes < 0 { '-' } else { '+' }
    let total = if self.offset_minutes < 0 {
      -self.offset_minutes
    } else {
      self.offset_minutes
    }
    sb.write_char(sign)
    sb.write_string(pad2(total / 60))
    sb.write_char(':')
    sb.write_string(pad2(total % 60))
  }
  sb.to_string()
}

///|
/// Parse the RFC 3339 `date-time` production used by RFC 9116.
pub fn parse_rfc3339(value : String) -> Result[DateTime, SecurityTxtError] {
  Ok(parse_rfc3339_inner(value)) catch {
    e => Err(unwrap_security_txt_error(e))
  }
}

///|
/// Raise-based core of `parse_rfc3339`.
fn parse_rfc3339_inner(value : String) -> DateTime raise {
  let len = value.length()
  if len < 20 {
    raise invalid_datetime(0, "value too short for an RFC 3339 date-time")
  }
  // Full-date: YYYY-MM-DD
  let year = parse_digits(value, 0, 4, "year")
  expect_char(value, 4, '-')
  let month = parse_digits(value, 5, 2, "month")
  expect_char(value, 7, '-')
  let day = parse_digits(value, 8, 2, "day")
  if month < 1 || month > 12 {
    raise invalid_datetime(5, "month must be between 01 and 12")
  }
  if day < 1 || day > days_in_month(year, month) {
    raise invalid_datetime(8, "day is out of range for the given month")
  }
  // RFC 3339 permits lower-case `t`, but RFC 9116 imports the date-time
  // production rather than the prose-only readability substitution of SP.
  let sep = char_at(value, 10)
  if sep != 'T' && sep != 't' {
    raise invalid_datetime(10, "expected 'T' between date and time")
  }
  if len < 19 {
    raise invalid_datetime(10, "value too short for a full-time")
  }
  let hour = parse_digits(value, 11, 2, "hour")
  expect_char(value, 13, ':')
  let minute = parse_digits(value, 14, 2, "minute")
  expect_char(value, 16, ':')
  let second = parse_digits(value, 17, 2, "second")
  if hour > 23 {
    raise invalid_datetime(11, "hour must be between 00 and 23")
  }
  if minute > 59 {
    raise invalid_datetime(14, "minute must be between 00 and 59")
  }
  if second > 60 {
    raise invalid_datetime(17, "second must be between 00 and 60")
  }
  let mut pos = 19
  // Optional fractional seconds.
  let mut nanos = 0L
  if pos < len && char_at(value, pos) == '.' {
    pos += 1
    let frac_start = pos
    let mut digits = 0
    while pos < len && char_at(value, pos).is_digit(10) {
      digits += 1
      pos += 1
    }
    if digits == 0 {
      raise invalid_datetime(
        frac_start, "expected digits after the decimal point",
      )
    }
    if digits > RFC3339_MAX_FRACTIONAL_DIGITS {
      raise invalid_datetime(
        frac_start, "more than 9 fractional digits are not supported",
      )
    }
    let mut scaled = 0L
    let mut _f = frac_start
    while _f < frac_start + digits {
      scaled = scaled * 10L + (char_at(value, _f).to_int() - 48).to_int64()
      _f += 1
    }
    let mut mult = 1_000_000_000L
    let mut _scale_i = 0
    while _scale_i < digits {
      mult /= 10L
      _scale_i += 1
    }
    nanos = scaled * mult
  }
  // Time offset: Z / z / ±HH:MM.
  if pos >= len {
    raise invalid_datetime(pos, "missing time offset (expected Z or ±HH:MM)")
  }
  let offset_sign = match char_at(value, pos) {
    'Z' | 'z' => {
      pos += 1
      0
    }
    '+' => {
      pos += 1
      1
    }
    '-' => {
      pos += 1
      -1
    }
    _ => raise invalid_datetime(pos, "expected time offset (Z or ±HH:MM)")
  }
  let mut offset_minutes = 0
  if offset_sign != 0 {
    if len < pos + 5 {
      raise invalid_datetime(pos, "numeric offset must be ±HH:MM")
    }
    let oh = parse_digits(value, pos, 2, "offset hour")
    expect_char(value, pos + 2, ':')
    let om = parse_digits(value, pos + 3, 2, "offset minute")
    if oh > 23 {
      raise invalid_datetime(pos, "offset hour must be between 00 and 23")
    }
    if om > 59 {
      raise invalid_datetime(pos + 3, "offset minute must be between 00 and 59")
    }
    offset_minutes = offset_sign * (oh * 60 + om)
    pos += 5
  }
  if pos != len {
    raise invalid_datetime(pos, "unexpected trailing characters")
  }
  { year, month, day, hour, minute, second, nanos, offset_minutes }
}

///|
fn invalid_datetime(offset : Int, message : String) -> SecurityTxtError {
  security_txt_error(DateTime, InvalidDateTime, 0, offset + 1, offset, message)
}

///|
/// Parse `length` ASCII digits at `start` into an Int.
fn parse_digits(
  value : String,
  start : Int,
  length : Int,
  what : String,
) -> Int raise {
  let mut n = 0
  let mut i = start
  while i < start + length {
    let c = char_at(value, i)
    if c.is_digit(10) {
      n = n * 10 + (c.to_int() - 48)
    } else {
      raise invalid_datetime(i, "\{what} must be ASCII digits")
    }
    i += 1
  }
  n
}

///|
fn expect_char(value : String, at : Int, expected : Char) -> Unit raise {
  let c = char_at(value, at)
  if c != expected {
    raise invalid_datetime(at, "expected '\{expected}'")
  }
}

///|
fn char_at(value : String, at : Int) -> Char raise {
  if at >= value.length() {
    raise invalid_datetime(at, "unexpected end of value")
  }
  let mut i = 0
  for c in value {
    if i == at {
      return c
    }
    i += 1
  }
  raise invalid_datetime(at, "unexpected end of value")
}

///|
fn pad2(n : Int) -> String {
  if n < 10 {
    "0\{n}"
  } else {
    n.to_string()
  }
}

///|
fn pad4(n : Int) -> String {
  if n < 10 {
    "000\{n}"
  } else if n < 100 {
    "00\{n}"
  } else if n < 1000 {
    "0\{n}"
  } else {
    n.to_string()
  }
}

///|
/// Days in the given month, respecting leap years (proleptic Gregorian).
pub fn days_in_month(year : Int, month : Int) -> Int {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31
    4 | 6 | 9 | 11 => 30
    2 => if is_leap_year(year) { 29 } else { 28 }
    _ => 0
  }
}

///|
/// Proleptic Gregorian leap year test.
pub fn is_leap_year(year : Int) -> Bool {
  year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

///|
/// Days from 1970-01-01 to the civil date (Howard Hinnant's `days_from_civil`).
pub fn days_from_civil(year : Int, month : Int, day : Int) -> Int64 {
  let y = if month <= 2 { year - 1 } else { year }
  let era = (if y >= 0 { y } else { y - 399 }) / 400
  let yoe = y - era * 400
  let mp = (month + 9) % 12
  let doy = (153 * mp + 2) / 5 + day - 1
  let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
  era.to_int64() * 146097L + doe.to_int64() - 719468L
}
