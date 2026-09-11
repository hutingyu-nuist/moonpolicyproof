///|
test "versioned DSL parses comments CRLF and tabs" {
  let p = Policy::parse(
    "# example\r\nmoonpolicyproof 1\r\ndefault deny\nrule web allow tcp 10.0.0.0/8 192.0.2.1/32 * 443\n",
  )
  assert_eq(p.rule_count(), 1)
  assert_eq(
    p.evaluate(Packet::new("10.2.3.4", "192.0.2.1", Tcp, 20, 443)).action,
    Allow,
  )
  assert_eq(Policy::parse("moonpolicyproof\t1\ndefault allow").rule_count(), 0)
}

///|
test "parser rejects ambiguity unsupported versions and invalid syntax" {
  for
    s in [
      "", "moonpolicyproof 2\ndefault deny", "moonpolicyproof 1", "moonpolicyproof 1\ndefault deny\ndefault allow",
      "moonpolicyproof 1\ndefault deny\nunknown x", "moonpolicyproof 1\ndefault deny\nrule a allow icmp 0.0.0.0/0 0.0.0.0/0 * *",
      "moonpolicyproof 1\ndefault 拒绝",
    ] {
    try Policy::parse(s) catch {
      Invalid(_) => ()
      e => raise e
    } noraise {
      _ => fail("invalid DSL accepted")
    }
  }
}

///|
test "diagnostic contains source line number" {
  try
    Policy::parse(
      "moonpolicyproof 1\ndefault deny\nrule x allow tcp bad 0.0.0.0/0 * *",
    )
  catch {
    Invalid(e) => assert_true(e.has_prefix("line 3:"))
    e => raise e
  } noraise {
    _ => fail("invalid address accepted")
  }
}
