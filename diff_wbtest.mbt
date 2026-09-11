///|
test "semantic diff ignores rule names but detects order effects" {
  let a = Policy::parse(
    "moonpolicyproof 1\ndefault deny\nrule a allow tcp 10.0.0.0/8 0.0.0.0/0 * 443",
  )
  let renamed = Policy::parse(
    "moonpolicyproof 1\ndefault deny\nrule renamed allow tcp 10.0.0.0/8 0.0.0.0/0 * 443",
  )
  assert_true(compare(a, renamed).equivalent())
  let blocked = Policy::parse(
    "moonpolicyproof 1\ndefault deny\nrule block deny any 0.0.0.0/0 0.0.0.0/0 * *\nrule a allow tcp 10.0.0.0/8 0.0.0.0/0 * 443",
  )
  let d = compare(a, blocked)
  assert_false(d.equivalent())
  assert_true(d.denied_witness() is Some(_))
  assert_eq(d.allowed_witness(), None)
}

///|
test "bidirectional changes yield independently replayed witnesses" {
  let old = Policy::parse(
    "moonpolicyproof 1\ndefault deny\nrule x allow tcp 0.0.0.0/0 0.0.0.0/0 * 80",
  )
  let next = Policy::parse(
    "moonpolicyproof 1\ndefault deny\nrule x allow tcp 0.0.0.0/0 0.0.0.0/0 * 443",
  )
  let d = compare(old, next)
  let allow = d.allowed_witness().unwrap()
  let deny = d.denied_witness().unwrap()
  assert_eq(allow.packet.destination_port, 443)
  assert_eq(deny.packet.destination_port, 80)
  assert_eq(allow.before.action, Deny)
  assert_eq(allow.after.action, Allow)
  assert_true(d.node_count() > 2)
}
