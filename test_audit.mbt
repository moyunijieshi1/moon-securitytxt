// Audit layer tests: advisory findings for freshness, missing optional
// fields, canonical mismatches, insecure URIs, duplicate singletons,
// unknown extensions, contexts and signature state.

///|
fn now_2026() -> DateTime raise {
  unwrap_datetime(make_utc(2026, 6, 1, 0, 0, 0))
}

///|
fn parse_and_audit(input : String) -> Array[AuditFinding] raise {
  let document = unwrap_parse(input)
  audit(document, now_2026(), empty_context())
}

///|
test "audit reports expired documents" {
  let findings = parse_and_audit(
    "Contact: mailto:a@example.com\nExpires: 2020-01-01T00:00:00Z\n",
  )
  assert_true(has_finding(findings, Expired))
  assert_false(has_finding(findings, ExpiresSoon))
}

///|
test "audit reports expires-soon within 30 days and stays quiet beyond" {
  let soon = parse_and_audit(
    "Contact: mailto:a@example.com\nExpires: 2026-06-30T00:00:00Z\n",
  )
  assert_true(has_finding(soon, ExpiresSoon))
  let later = parse_and_audit(
    "Contact: mailto:a@example.com\nExpires: 2026-07-03T00:00:00Z\n",
  )
  assert_false(has_finding(later, Expired))
  assert_false(has_finding(later, ExpiresSoon))
  assert_true(EXPIRES_SOON_SECONDS == 30L * 24L * 60L * 60L)
}

///|
test "audit reports missing optional fields" {
  let findings = parse_and_audit(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\n",
  )
  assert_true(has_finding(findings, NoPolicy))
  assert_true(has_finding(findings, NoCanonical))
  assert_true(has_finding(findings, NoPreferredLanguages))
}

///|
test "audit reports canonical mismatches and invalid retrieval contexts" {
  let document = unwrap_parse(
    "Canonical: https://example.com/.well-known/security.txt\nContact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\n",
  )
  let context = security_txt_context(
    Some("https://other.example.com/.well-known/security.txt"),
    None,
  )
  let findings = audit(document, now_2026(), context)
  assert_true(has_finding(findings, CanonicalMismatch))
  let valid = unwrap_parse(valid_document())
  let bad_context = security_txt_context(Some("http://example.com/x"), None)
  let context_findings = audit(valid, now_2026(), bad_context)
  assert_true(has_finding(context_findings, InvalidContext))
}

///|
test "audit reports insecure http URIs" {
  let findings = parse_and_audit(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nPolicy: http://example.com/policy\n",
  )
  assert_true(has_finding(findings, InsecureWebUri))
}

///|
test "audit only reports RFC singleton duplicates and unknown extensions once per name" {
  let repeatable_findings = parse_and_audit(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nCanonical: https://a.example.com/.well-known/security.txt\nCanonical: https://b.example.com/.well-known/security.txt\n",
  )
  assert_false(has_finding(repeatable_findings, DuplicateSingletonField))
  let dup_findings = parse_and_audit(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nExpires: 2028-01-01T00:00:00Z\n",
  )
  assert_true(has_finding(dup_findings, DuplicateSingletonField))
  let ext_findings = parse_and_audit(
    "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nFoo-Bar: 1\nFoo-Bar: 2\nBaz: 3\n",
  )
  let mut count = 0
  for finding in ext_findings {
    if finding.kind() == UnknownExtension {
      count += 1
    }
  }
  assert_int_eq(count, 2)
}

///|
test "audit reports unsigned documents and stays quiet about signed ones" {
  let findings = parse_and_audit(valid_document())
  assert_true(has_finding(findings, Unsigned))
  let signed = "-----BEGIN PGP SIGNED MESSAGE-----\n\nContact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\n-----BEGIN PGP SIGNATURE-----\n\nfake\n-----END PGP SIGNATURE-----\n"
  let document = unwrap_parse(signed)
  let signed_findings = audit(document, now_2026(), empty_context())
  assert_false(has_finding(signed_findings, Unsigned))
}

///|
test "audit findings carry stable labels, severities and messages" {
  assert_str_eq(Expired.label(), "expired")
  assert_str_eq(ExpiresSoon.label(), "expires-soon")
  assert_str_eq(NoPolicy.label(), "no-policy")
  assert_str_eq(NoCanonical.label(), "no-canonical")
  assert_str_eq(CanonicalMismatch.label(), "canonical-mismatch")
  assert_str_eq(InsecureWebUri.label(), "insecure-web-uri")
  assert_str_eq(DuplicateSingletonField.label(), "duplicate-singleton-field")
  assert_str_eq(UnknownExtension.label(), "unknown-extension")
  assert_str_eq(NoPreferredLanguages.label(), "no-preferred-languages")
  assert_str_eq(AuditFindingKind::InvalidContext.label(), "invalid-context")
  assert_str_eq(AuditFindingKind::Unsigned.label(), "unsigned")
  assert_str_eq(Info.label(), "info")
  assert_str_eq(Warning.label(), "warning")
  let expired_findings = parse_and_audit(
    "Contact: mailto:a@example.com\nExpires: 2020-01-01T00:00:00Z\n",
  )
  let mut expired = false
  for finding in expired_findings {
    if finding.kind() == Expired {
      expired = true
      assert_true(finding.severity() == Warning)
      assert_true(finding.message().length() > 0)
      assert_int_eq(finding.line(), 0)
    }
  }
  assert_true(expired)
}
