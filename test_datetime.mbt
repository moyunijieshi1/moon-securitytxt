// RFC 3339 date-time tests: construction ranges, parsing, formatting,
// epoch arithmetic and cross-offset comparisons.

///|
test "make_utc accepts a valid date" {
  let dt = unwrap_datetime(make_utc(2026, 8, 13, 14, 30, 59))
  assert_int_eq(dt.year(), 2026)
  assert_int_eq(dt.month(), 8)
  assert_int_eq(dt.day(), 13)
  assert_int_eq(dt.hour(), 14)
  assert_int_eq(dt.minute(), 30)
  assert_int_eq(dt.second(), 59)
  assert_true(dt.nanos() == 0L)
  assert_int_eq(dt.offset_minutes(), 0)
}

///|
test "make_utc rejects out-of-range components" {
  assert_true(make_utc(2026, 0, 1, 0, 0, 0) is Err(_))
  assert_true(make_utc(2026, 13, 1, 0, 0, 0) is Err(_))
  assert_true(make_utc(2026, 1, 0, 0, 0, 0) is Err(_))
  assert_true(make_utc(2026, 1, 32, 0, 0, 0) is Err(_))
  assert_true(make_utc(2026, 4, 31, 0, 0, 0) is Err(_))
  assert_true(make_utc(2026, 1, 1, 24, 0, 0) is Err(_))
  assert_true(make_utc(2026, 1, 1, 0, 60, 0) is Err(_))
  assert_true(make_utc(2026, 1, 1, 0, 0, 61) is Err(_))
  assert_true(make_utc(2026, 1, 1, -1, 0, 0) is Err(_))
}

///|
test "make_utc follows the leap year rules for February 29" {
  assert_true(make_utc(2024, 2, 29, 0, 0, 0) is Ok(_))
  assert_true(make_utc(2023, 2, 29, 0, 0, 0) is Err(_))
  assert_true(make_utc(1900, 2, 29, 0, 0, 0) is Err(_))
  assert_true(make_utc(2000, 2, 29, 0, 0, 0) is Ok(_))
}

///|
test "make_utc accepts leap seconds and rejects bad nanos" {
  let dt = unwrap_datetime(make_utc(2026, 8, 13, 0, 0, 60))
  assert_int_eq(dt.second(), 60)
  assert_true(make_utc_nanos(2026, 1, 1, 0, 0, 0, -1L) is Err(_))
  assert_true(make_utc_nanos(2026, 1, 1, 0, 0, 0, 1_000_000_000L) is Err(_))
  assert_true(make_utc_nanos(2026, 1, 1, 0, 0, 0, 999_999_999L) is Ok(_))
}

///|
test "is_leap_year and days_in_month cover the calendar tables" {
  assert_true(is_leap_year(2024))
  assert_true(is_leap_year(2000))
  assert_false(is_leap_year(1900))
  assert_false(is_leap_year(2023))
  assert_false(is_leap_year(2100))
  assert_int_eq(days_in_month(2026, 1), 31)
  assert_int_eq(days_in_month(2026, 2), 28)
  assert_int_eq(days_in_month(2024, 2), 29)
  assert_int_eq(days_in_month(2026, 4), 30)
  assert_int_eq(days_in_month(2026, 6), 30)
  assert_int_eq(days_in_month(2026, 12), 31)
}

///|
test "parse_rfc3339 accepts RFC 9116 date-time separators" {
  assert_true(parse_rfc3339("2026-08-13T14:30:59Z") is Ok(_))
  assert_true(parse_rfc3339("2026-08-13T14:30:59z") is Ok(_))
  assert_true(parse_rfc3339("2026-08-13t14:30:59Z") is Ok(_))
  assert_true(parse_rfc3339("2026-08-13") is Err(_))
  assert_true(parse_rfc3339("2026-08-13 14:30:59Z") is Err(_))
}

///|
test "parse_rfc3339 accepts numeric offsets and fractional seconds" {
  let plus = unwrap_datetime(parse_rfc3339("2026-08-13T14:30:59+08:00"))
  let minus = unwrap_datetime(parse_rfc3339("2026-08-13T14:30:59-05:00"))
  assert_int_eq(plus.offset_minutes(), 480)
  assert_int_eq(minus.offset_minutes(), -300)
  let dt = unwrap_datetime(parse_rfc3339("2026-08-13T00:00:00.5Z"))
  assert_true(dt.nanos() == 500_000_000L)
  let dt2 = unwrap_datetime(parse_rfc3339("2026-08-13T00:00:00.123456789Z"))
  assert_true(dt2.nanos() == 123_456_789L)
}

///|
test "parse_rfc3339 rejects invalid calendar dates" {
  assert_true(parse_rfc3339("2026-13-01T00:00:00Z") is Err(_))
  assert_true(parse_rfc3339("2026-02-30T00:00:00Z") is Err(_))
  assert_true(parse_rfc3339("2023-02-29T00:00:00Z") is Err(_))
  assert_true(parse_rfc3339("2026-08-13T24:00:00Z") is Err(_))
  assert_true(parse_rfc3339("2026-08-13T00:61:00Z") is Err(_))
}

///|
test "parse_rfc3339 rejects missing offsets, trailing junk and long fractions" {
  assert_true(parse_rfc3339("2026-08-13T14:30:59") is Err(_))
  assert_true(parse_rfc3339("2026-08-13T14:30:59Z ") is Err(_))
  assert_true(parse_rfc3339("2026-08-13X") is Err(_))
  assert_true(parse_rfc3339("2026-08-13T00:00:00.1234567890Z") is Err(_))
  assert_true(parse_rfc3339("2026-08-13T00:00:00.Z") is Err(_))
}

///|
test "parse_rfc3339 errors carry byte offsets" {
  match parse_rfc3339("2026-13-01T00:00:00Z") {
    Ok(_) => fail("expected an error for month 13")
    Err(err) => {
      assert_err_kind(err, InvalidDateTime)
      assert_int_eq(err.byte_offset(), 5)
    }
  }
}

///|
test "format_rfc3339 renders canonical and offset forms" {
  let dt = unwrap_datetime(make_utc_nanos(2026, 8, 13, 7, 5, 9, 125_000_000L))
  assert_str_eq(dt.format_rfc3339(), "2026-08-13T07:05:09.125Z")
  let whole = unwrap_datetime(make_utc(2026, 8, 13, 7, 5, 9))
  assert_str_eq(whole.format_rfc3339(), "2026-08-13T07:05:09Z")
  match parse_rfc3339("2026-08-13T14:30:59+08:00") {
    Ok(d) => assert_str_eq(d.format_rfc3339(), "2026-08-13T14:30:59+08:00")
    Err(_) => fail("unexpected parse failure")
  }
}

///|
test "epoch conversion matches well-known instants across offsets" {
  let epoch = unwrap_datetime(make_utc(1970, 1, 1, 0, 0, 0))
  assert_true(epoch.to_epoch_nanos() == 0L)
  let y2k = unwrap_datetime(make_utc(2000, 1, 1, 0, 0, 0))
  assert_true(y2k.to_epoch_nanos() == 946_684_800_000_000_000L)
  let y2020 = unwrap_datetime(make_utc(2020, 1, 1, 0, 0, 0))
  assert_true(y2020.to_epoch_nanos() == 1_577_836_800_000_000_000L)
  let utc = unwrap_datetime(parse_rfc3339("2026-08-13T00:00:00Z"))
  let beijing = unwrap_datetime(parse_rfc3339("2026-08-13T08:00:00+08:00"))
  assert_true(utc.equals(beijing))
  assert_false(utc.before(beijing))
  assert_false(utc.after(beijing))
}

///|
test "is_expired, time_until_expiry and div_floor work at the boundary" {
  let expires = unwrap_datetime(make_utc(2026, 6, 1, 0, 0, 0))
  let before = unwrap_datetime(make_utc(2026, 5, 31, 23, 59, 59))
  let at = unwrap_datetime(make_utc(2026, 6, 1, 0, 0, 0))
  let after = unwrap_datetime(make_utc(2026, 6, 1, 0, 0, 1))
  assert_false(is_expired(expires, before))
  assert_false(is_expired(expires, at))
  assert_true(is_expired(expires, after))
  assert_true(time_until_expiry(expires, before) == 1L)
  assert_true(time_until_expiry(expires, at) == 0L)
  assert_true(time_until_expiry(expires, after) == -1L)
  assert_true(div_floor_i64(7L, 2L) == 3L)
  assert_true(div_floor_i64(-7L, 2L) == -4L)
  assert_true(div_floor_i64(7L, -2L) == -4L)
  assert_true(div_floor_i64(-7L, -2L) == 3L)
  assert_true(div_floor_i64(1_500_000_000L, 1_000_000_000L) == 1L)
  assert_true(div_floor_i64(-1_500_000_000L, 1_000_000_000L) == -2L)
}
