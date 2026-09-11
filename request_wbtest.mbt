///|
test "request contract has distinct change invalid and resource outcomes" {
  let old = "moonpolicyproof 1\ndefault deny"
  let next = "moonpolicyproof 1\ndefault allow"
  let (code, body) = handle_request(
    ({ "command": "diff", "before": old, "after": next } : Json).stringify(),
  )
  assert_eq(code, 1)
  assert_true(body.contains("moonpolicyproof.comparison.v1"))
  assert_eq(handle_request("{broken").0, 2)
  assert_eq(
    handle_request(
      (
        { "command": "diff", "before": old, "after": next, "scpoe": "oops" } :
        Json).stringify(),
    ).0,
    2,
  )
  let policy = "moonpolicyproof 1\ndefault deny\nrule x allow tcp 10.0.0.0/8 0.0.0.0/0 * 443"
  let (code, body) = handle_request(
    ({ "command": "audit", "policy": policy, "max_nodes": 2 } : Json).stringify(),
  )
  assert_eq(code, 3)
  assert_false(body.contains("equivalent"))
  assert_true(body.contains("resource"))
}

///|
test "request scope is included with bounded equality claim" {
  let (code, body) = handle_request(
    (
      {
        "command": "diff",
        "before": "moonpolicyproof 1\ndefault deny",
        "after": "moonpolicyproof 1\ndefault deny",
        "scope": "udp 0.0.0.0/0 0.0.0.0/0 * 53",
      } : Json).stringify(),
  )
  assert_eq(code, 0)
  assert_true(body.contains("udp 0.0.0.0/0 0.0.0.0/0 * 53"))
}
