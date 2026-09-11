///|
test "canonical export normalizes CIDR and preserves ordered meaning" {
  let p = Policy::parse(
    "moonpolicyproof 1\ndefault deny\nrule first allow tcp 10.0.0.99/24 0.0.0.0/0 00080 00443\nrule second deny any 0.0.0.0/0 0.0.0.0/0 * *",
  )
  let text = p.render()
  assert_eq(
    text, "moonpolicyproof 1\ndefault deny\nrule first allow tcp 10.0.0.0/24 0.0.0.0/0 80 443\nrule second deny any 0.0.0.0/0 0.0.0.0/0 * *\n",
  )
  assert_eq(Policy::parse(text), p)
  assert_eq(Policy::parse(text).render(), text)
}
