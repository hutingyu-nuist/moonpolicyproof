///|
test "scope excludes unrelated drift without claiming global equality" {
  let old = Policy::new([], Deny)
  let next = Policy::parse(
    "moonpolicyproof 1\ndefault deny\nrule web allow tcp 0.0.0.0/0 0.0.0.0/0 * 443",
  )
  let dns = Scope::parse("udp 0.0.0.0/0 0.0.0.0/0 * 53")
  assert_false(compare(old, next).equivalent())
  assert_true(compare_scoped(old, next, dns).equivalent())
  assert_eq(next.find_scoped(Allow, dns), None)
  let web = Scope::parse("tcp 192.0.2.0/24 198.51.100.1/32 40000-50000 443")
  let w = compare_scoped(old, next, web).allowed_witness().unwrap()
  assert_true(web.contains(w.packet))
  assert_eq(Scope::parse(web.render()), web)
}
