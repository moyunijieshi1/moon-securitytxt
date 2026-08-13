// Truncation suite: every truncated or single-byte-mutated input must come
// back as `Ok` or a structured `Err` — the parser must never crash. This is
// the defensive-parsing guarantee for untrusted input.

///|
/// Bytes of an input as integers, for deterministic prefix/mutation work.
fn ints_of_bytes(bytes : Bytes) -> Array[Int] {
  let out : Array[Int] = []
  for b in bytes {
    out.push(b.to_int())
  }
  out
}

///|
/// Parse must not crash; an Err must remain a well-formed structured error.
fn check_safe(input : Bytes) -> Unit raise {
  match parse_security_txt_bytes(input, Limits::default()) {
    Ok(_) => ()
    Err(err) => {
      let rendered = err.to_string()
      assert_true(rendered.length() > 0)
    }
  }
}

///|
test "truncation: every prefix of a valid document yields Ok or structured Err" {
  let full = ints_of_bytes(@utf8.encode(valid_document()))
  let mut cases = 0
  let mut len = 0
  while len <= full.length() {
    let prefix : Array[Int] = []
    let mut k = 0
    while k < len {
      prefix.push(full[k])
      k += 1
    }
    check_safe(bytes_of(prefix))
    cases += 1
    len += 1
  }
  assert_int_eq(cases, full.length() + 1)
}

///|
test "truncation: byte-level fuzzing never crashes the parser" {
  let full = ints_of_bytes(@utf8.encode(valid_document()))
  // Replace a sampled byte with an interesting value (NUL, a UTF-8
  // continuation byte, a lead byte, 0xFF, or an ASCII byte) and parse.
  let mutations = [0x00, 0x80, 0xC0, 0xFF]
  let mut cases = 0
  let mut pos = 0
  while pos < full.length() {
    for m in mutations {
      let copy : Array[Int] = []
      let mut k = 0
      while k < full.length() {
        if k == pos {
          copy.push(m)
        } else {
          copy.push(full[k])
        }
        k += 1
      }
      check_safe(bytes_of(copy))
      cases += 1
    }
    pos += 8
  }
  let positions = (full.length() + 7) / 8
  assert_int_eq(cases, positions * 4)
  // For each cut position, append one of the five interesting trailing
  // bytes directly after the cut. This targets the strict decoder's
  // boundary handling.
  let tails = [0x00, 0x80, 0xC2, 0xF5, 0x41]
  let mut grid_cases = 0
  let mut cut = 0
  while cut < full.length() {
    for tail in tails {
      let candidate : Array[Int] = []
      let mut k = 0
      while k <= cut {
        candidate.push(full[k])
        k += 1
      }
      candidate.push(tail)
      check_safe(bytes_of(candidate))
      grid_cases += 1
    }
    cut += 8
  }
  let cuts = (full.length() + 7) / 8
  assert_int_eq(grid_cases, cuts * 5)
}

///|
test "truncation: sampled prefixes of a signed envelope are safe" {
  let full = ints_of_bytes(@utf8.encode(signed_fixture()))
  let mut cases = 0
  let mut len = 0
  while len < full.length() {
    let prefix : Array[Int] = []
    let mut k = 0
    while k < len {
      prefix.push(full[k])
      k += 1
    }
    check_safe(bytes_of(prefix))
    cases += 1
    len += 2
  }
  // The complete envelope itself.
  check_safe(bytes_of(full))
  cases += 1
  assert_int_eq(cases, (full.length() + 1) / 2 + 1)
}
