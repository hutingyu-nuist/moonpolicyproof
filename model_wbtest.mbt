///|
test "policy snapshots caller array and enforces unique ids" {
  let r = Rule::new(
    "web",
    Allow,
    Some(Tcp),
    "10.0.0.1/24",
    "0.0.0.0/0",
    Ports::any(),
    Ports::parse("443"),
  )
  let rs = [r]
  let p = Policy::new(rs, Deny)
  rs.clear()
  assert_eq(p.rule_count(), 1)
  try Policy::new([r, r], Deny) catch {
    Invalid(_) => ()
    e => raise e
  } noraise {
    _ => fail("duplicate accepted")
  }
}

///|
test "packet rejects unsupported address and port domain" {
  try Packet::new("::1", "1.2.3.4", Tcp, 0, 80) catch {
    Invalid(_) => ()
    e => raise e
  } noraise {
    _ => fail("IPv6 accepted")
  }
  try Packet::new("0.0.0.0", "255.255.255.255", Udp, 0, 65536) catch {
    Invalid(_) => ()
    e => raise e
  } noraise {
    _ => fail("invalid port accepted")
  }
  let p = Packet::new("0.0.0.0", "255.255.255.255", Udp, 0, 65535)
  assert_eq(p.fields(), ("0.0.0.0", "255.255.255.255", Udp, 0, 65535))
}
