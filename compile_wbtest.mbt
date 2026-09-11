///|
test "symbolic compiler honors first-match deny and both defaults" {
  let p = Policy::parse(
    "moonpolicyproof 1\ndefault deny\nrule block deny any 0.0.0.0/0 0.0.0.0/0 * *\nrule later allow tcp 10.0.0.0/8 0.0.0.0/0 * 443",
  )
  assert_eq(p.find(Allow), None)
  assert_true(p.find(Deny) is Some(_))
  assert_eq(Policy::new([], Allow).find(Deny), None)
  assert_eq(Policy::new([], Deny).find(Allow), None)
}

///|
test "default allows only unmatched complement" {
  let p = Policy::parse(
    "moonpolicyproof 1\ndefault allow\nrule block deny tcp 0.0.0.0/0 0.0.0.0/0 * 443",
  )
  let allowed = p.find(Allow).unwrap()
  let denied = p.find(Deny).unwrap()
  assert_eq(p.evaluate(allowed).action, Allow)
  assert_eq(p.evaluate(denied).rule_id, Some("block"))
}
