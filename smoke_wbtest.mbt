///|
test "pinned libraries compose on shared pure targets" {
  let net = @cidr.CidrBlock::parse("192.0.2.9/24").unwrap()
  assert_true(net.contains_ip(@cidr.IPv4::parse("192.0.2.1").unwrap()))
  let m = @bdd.Manager::new(["x"], @bdd.ResourceBudget::default()).unwrap()
  let x = m.variable("x").unwrap()
  assert_true(m.is_false(m.and_bdd(x, m.not_bdd(x).unwrap()).unwrap()))
}
