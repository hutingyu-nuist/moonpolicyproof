///|
test "versioned JSON reports preserve typed witnesses and explicit nulls" {
  let d = compare(Policy::new([], Deny), Policy::new([], Allow))
  let j = d.to_json()
  guard j
    is {
      "schema": String(schema),
      "equivalent": False,
      "newly_allowed": { "replayed": True, .. },
      "newly_denied": Null,
      ..
    } else {
    fail("report schema changed")
  }
  assert_eq(schema, "moonpolicyproof.diff.v1")
  assert_true(d.render().contains("newly denied: none"))
  assert_eq(audit_json([]), {
    "schema": "moonpolicyproof.audit.v1",
    "rules": [],
  })
}
