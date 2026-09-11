///|
test "predicate witness replays every coordinate including all-ones IPv4" {
  for proto in [None, Some(Tcp), Some(Udp)] {
    for cidr in ["0.0.0.0/0", "255.255.255.255/32", "192.0.2.128/25"] {
      let r = Rule::new(
        "x",
        Allow,
        proto,
        cidr,
        "198.51.100.0/24",
        Ports::parse("32767-32769"),
        Ports::parse("65535"),
      )
      let p = r.witness()
      assert_true(r.matches(p))
      assert_eq(p.destination_port, 65535)
    }
  }
}

///|
test "port BDD agrees exhaustively with a scalar comparator" {
  let e = Engine::new(100000)
  for
    interval in [
      Ports::new(0, 0),
      Ports::new(65535, 65535),
      Ports::new(17, 39),
      Ports::new(32767, 32769),
      Ports::any(),
    ] {
    let b = e.ports(interval, 81)
    for n = 0; n < 65536; n = n + 1 {
      let bits = e.manager.variable_names().map(name => (name, false))
      for i = 0; i < 16; i = i + 1 {
        bits[81 + i] = ("b" + (81 + i).to_string(), ((n >> (15 - i)) & 1) == 1)
      }
      assert_eq(bdd_value(e.manager.evaluate(b, bits)), interval.contains(n))
    }
  }
}

///|
test "node exhaustion is an error rather than no witness" {
  let r = Rule::new(
    "x",
    Allow,
    None,
    "1.2.3.4/32",
    "5.6.7.8/32",
    Ports::any(),
    Ports::any(),
  )
  try r.witness(max_nodes=2) catch {
    Resource(_) => ()
    e => raise e
  } noraise {
    _ => fail("budget exhaustion hidden")
  }
}
