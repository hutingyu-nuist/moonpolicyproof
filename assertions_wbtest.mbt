///|
test "regression suite checks universal decisions and explains failure" {
  let p = Policy::parse(
    "moonpolicyproof 1\ndefault deny\nrule web allow tcp 0.0.0.0/0 0.0.0.0/0 * 443",
  )
  let suite = parse_assertions(
    "assert web allow tcp 0.0.0.0/0 0.0.0.0/0 * 443\nassert ssh deny tcp 0.0.0.0/0 0.0.0.0/0 * 22\nassert block-web deny tcp 0.0.0.0/0 0.0.0.0/0 * 443",
  )
  let r = p.check_assertions(suite)
  assert_true(r[0].passed && r[1].passed)
  assert_false(r[2].passed)
  assert_eq(r[2].actual.unwrap().rule_id, Some("web"))
  assert_eq(r[2].counterexample.unwrap().destination_port, 443)
}

///|
test "empty and duplicate suites cannot silently pass" {
  try parse_assertions("# no assertions") catch {
    Invalid(_) => ()
    e => raise e
  } noraise {
    _ => fail("empty suite accepted")
  }
  let a = Assertion::new("x", Deny, Scope::parse("any 0.0.0.0/0 0.0.0.0/0 * *"))
  try Policy::new([], Deny).check_assertions([a, a]) catch {
    Invalid(_) => ()
    e => raise e
  } noraise {
    _ => fail("duplicate suite accepted")
  }
}
