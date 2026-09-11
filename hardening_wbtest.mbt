///|
test "public assertion API rejects vacuous empty success" {
  try Policy::new([], Deny).check_assertions([]) catch {
    Invalid(_) => ()
    e => raise e
  } noraise {
    _ => fail("empty assertion suite passed")
  }
}

///|
test "independent replay rejects forged direction as internal error" {
  let p = Packet::new("1.2.3.4", "5.6.7.8", Tcp, 20, 80)
  try
    replay_change(
      Some(p),
      Policy::new([], Allow),
      Policy::new([], Allow),
      Deny,
      Allow,
    )
  catch {
    Internal(_) => ()
    e => raise e
  } noraise {
    _ => fail("forged witness accepted")
  }
}

///|
test "JSON depth and invalid node budgets are rejected without success payload" {
  for
    text in [
      "[[[[[[[[[0]]]]]]]]]", "{\"command\":\"audit\",\"policy\":\"moonpolicyproof 1\\ndefault deny\",\"max_nodes\":2.5}",
      "{\"command\":\"help\",\"extra\":0}",
    ] {
    let (code, body) = handle_request(text)
    assert_eq(code, 2)
    assert_false(body.contains("equivalent"))
  }
}

///|
test "a failed analysis cannot poison a later manager" {
  let p = Policy::parse(
    "moonpolicyproof 1\ndefault deny\nrule x allow tcp 10.0.0.0/8 0.0.0.0/0 * 443",
  )
  try compare(p, p, max_nodes=2) catch {
    Resource(_) => ()
    e => raise e
  } noraise {
    _ => fail("expected exhaustion")
  }
  assert_true(compare(p, p).equivalent())
}
