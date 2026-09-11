///|
fn text_field(
  fields : Map[String, Json],
  key : String,
) -> String raise PolicyError {
  match fields.get(key) {
    Some(String(s)) => s
    _ => raise Invalid("missing or non-string field: " + key)
  }
}

///|
fn execute(request : Json) -> (Int, Json) raise PolicyError {
  guard request is Object(fields) else {
    raise Invalid("request must be an object")
  }
  let command = text_field(fields, "command")
  let allowed = match command {
    "help" => ["command"]
    "diff" => ["command", "before", "after", "scope", "max_nodes"]
    "audit" | "format" => ["command", "policy", "max_nodes"]
    "check" => ["command", "policy", "assertions", "max_nodes"]
    _ => raise Invalid("unknown command")
  }
  for key, _ in fields {
    if !allowed.contains(key) {
      raise Invalid("unknown field: " + key)
    }
  }
  let max_nodes = match fields.get("max_nodes") {
    None => 100000
    Some(Number(n, ..)) => {
      if n < 2.0 || n > 200000.0 || n != n.to_int().to_double() {
        raise Invalid("max_nodes must be an integer in 2..200000")
      }
      n.to_int()
    }
    _ => raise Invalid("max_nodes must be numeric")
  }
  match command {
    "help" =>
      (
        0,
        {
          "schema": "moonpolicyproof.help.v1",
          "usage": "diff BEFORE AFTER [SCOPE] | audit POLICY | check POLICY ASSERTIONS | format POLICY; diff/check exit 1 on changes/failures, 2 invalid input, 3 resource exhaustion",
        },
      )
    "format" =>
      (
        0,
        {
          "schema": "moonpolicyproof.format.v1",
          "policy": Policy::parse(text_field(fields, "policy")).render(),
        },
      )
    "audit" =>
      (
        0,
        audit_json(
          Policy::parse(text_field(fields, "policy")).audit(max_nodes~),
        ),
      )
    "check" => {
      let results = Policy::parse(text_field(fields, "policy")).check_assertions(
        parse_assertions(text_field(fields, "assertions")),
        max_nodes~,
      )
      (
        if results.iter().all(r => r.passed) {
          0
        } else {
          1
        },
        assertions_json(results),
      )
    }
    "diff" => {
      let before = Policy::parse(text_field(fields, "before"))
      let after = Policy::parse(text_field(fields, "after"))
      let scope = match fields.get("scope") {
        None => None
        Some(String(s)) => Some(Scope::parse(s))
        _ => raise Invalid("scope must be a string")
      }
      let diff = match scope {
        None => compare(before, after, max_nodes~)
        Some(s) => compare_scoped(before, after, s, max_nodes~)
      }
      // Scope is included in the envelope, so scoped equality is never presented as global equality.
      let body : Json = {
        "schema": "moonpolicyproof.comparison.v1",
        "scope": match scope {
          None => Json::null()
          Some(s) => Json::string(s.render())
        },
        "result": diff.to_json(),
      }
      (if diff.equivalent() { 0 } else { 1 }, body)
    }
    _ => raise Invalid("unknown command")
  }
}

///|
/// Host-neutral bounded JSON entry point. No partial success survives an error.
pub fn handle_request(text : String) -> (Int, String) {
  if text.length() > 400000 {
    return (
      2,
      (
        {
          "schema": "moonpolicyproof.error.v1",
          "category": "invalid",
          "message": "request too large",
        } : Json).stringify(),
    )
  }
  let request = parse_request_json(text) catch {
    _ =>
      return (
        2,
        (
          {
            "schema": "moonpolicyproof.error.v1",
            "category": "invalid",
            "message": "invalid JSON or nesting depth",
          } : Json).stringify(),
      )
  }
  try {
    let (code, body) = execute(request)
    (code, body.stringify())
  } catch {
    Invalid(message) =>
      (
        2,
        (
          {
            "schema": "moonpolicyproof.error.v1",
            "category": "invalid",
            "message": message,
          } : Json).stringify(),
      )
    Resource(message) =>
      (
        3,
        (
          {
            "schema": "moonpolicyproof.error.v1",
            "category": "resource",
            "message": message,
          } : Json).stringify(),
      )
  }
}
