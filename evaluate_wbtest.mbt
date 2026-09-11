///|
test "first matching rule wins and default has no invented rule id" {
  let deny = Rule::new(
    "block",
    Deny,
    Some(Tcp),
    "10.0.0.0/8",
    "0.0.0.0/0",
    Ports::any(),
    Ports::parse("443"),
  )
  let allow = Rule::new(
    "later",
    Allow,
    None,
    "0.0.0.0/0",
    "0.0.0.0/0",
    Ports::any(),
    Ports::any(),
  )
  let packet = Packet::new("10.1.2.3", "192.0.2.1", Tcp, 3000, 443)
  assert_eq(Policy::new([deny, allow], Allow).evaluate(packet), {
    action: Deny,
    rule_id: Some("block"),
    tested_rules: 1,
  })
  assert_eq(Policy::new([allow, deny], Deny).evaluate(packet).action, Allow)
  assert_eq(Policy::new([], Deny).evaluate(packet), {
    action: Deny,
    rule_id: None,
    tested_rules: 0,
  })
}

///|
test "every independent tuple coordinate can prevent a match" {
  let r = Rule::new(
    "x",
    Allow,
    Some(Tcp),
    "10.0.0.1/32",
    "192.0.2.1/32",
    Ports::parse("100"),
    Ports::parse("443"),
  )
  assert_true(r.matches(Packet::new("10.0.0.1", "192.0.2.1", Tcp, 100, 443)))
  for
    packet in [
      Packet::new("10.0.0.2", "192.0.2.1", Tcp, 100, 443),
      Packet::new("10.0.0.1", "192.0.2.2", Tcp, 100, 443),
      Packet::new("10.0.0.1", "192.0.2.1", Udp, 100, 443),
      Packet::new("10.0.0.1", "192.0.2.1", Tcp, 101, 443),
      Packet::new("10.0.0.1", "192.0.2.1", Tcp, 100, 444),
    ] {
    assert_false(r.matches(packet))
  }
}
