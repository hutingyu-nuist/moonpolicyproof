///|
test "union shadow is detected even when no individual rule subsumes later rule" {
  let p = Policy::parse(
    "moonpolicyproof 1\ndefault deny\nrule half1 deny any 10.0.0.0/25 0.0.0.0/0 * *\nrule half2 allow any 10.0.0.128/25 0.0.0.0/0 * *\nrule whole allow any 10.0.0.0/24 0.0.0.0/0 * *",
  )
  let audit = p.audit()
  assert_eq(audit[0].coverage, Reachable)
  assert_eq(audit[1].coverage, Reachable)
  assert_eq(audit[2].coverage, Shadowed)
  assert_eq(audit[2].reachable_witness, None)
  assert_true(audit[2].blocked_by is Some(_))
}

///|
test "partial coverage returns both reachable and blocked packets" {
  let p = Policy::parse(
    "moonpolicyproof 1\ndefault deny\nrule small deny tcp 10.0.0.0/25 0.0.0.0/0 * 443\nrule big allow tcp 10.0.0.0/24 0.0.0.0/0 * 443",
  )
  let a = p.audit()[1]
  assert_eq(a.coverage, Partial)
  assert_eq(a.blocked_by, Some("small"))
  assert_eq(p.evaluate(a.reachable_witness.unwrap()).rule_id, Some("big"))
  assert_eq(p.evaluate(a.blocked_witness.unwrap()).rule_id, Some("small"))
}
