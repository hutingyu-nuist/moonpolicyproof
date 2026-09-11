///|
test "inclusive port boundaries and canonical roundtrip" {
  for s in ["*", "0", "65535", "20-80"] {
    let p = Ports::parse(s)
    assert_eq(Ports::parse(p.render()), p)
    let (lo, hi) = p.bounds()
    assert_true(p.contains(lo) && p.contains(hi))
    assert_false(p.contains(lo - 1))
    assert_false(p.contains(hi + 1))
  }
}

///|
test "invalid intervals reject before arithmetic overflow" {
  for s in ["", "-1", "65536", "80-20", "1-2-3", "999999999999999", "+2", "1 "] {
    try Ports::parse(s) catch {
      Invalid(_) => ()
      e => raise e
    } noraise {
      _ => fail("invalid port accepted")
    }
  }
}
