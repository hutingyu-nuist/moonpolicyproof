///|
pub struct Assertion {
  id : String
  expected : Action
  scope : Scope
} derive(Eq, Debug)

///|
pub fn Assertion::new(
  id : String,
  expected : Action,
  scope : Scope,
) -> Assertion raise PolicyError {
  ignore(
    Rule::new(
      id,
      expected,
      None,
      "0.0.0.0/0",
      "0.0.0.0/0",
      Ports::any(),
      Ports::any(),
    ),
  )
  { id, expected, scope }
}

///|
pub(all) struct AssertionResult {
  id : String
  passed : Bool
  counterexample : Packet?
  actual : Decision?
} derive(Eq, Debug)

///|
/// A suite shares one compilation and budget; any error invalidates the entire run.
pub fn Policy::check_assertions(
  self : Policy,
  assertions : Array[Assertion],
  max_nodes? : Int = 100000,
) -> Array[AssertionResult] raise PolicyError {
  if assertions.length() > 64 {
    raise Invalid("at most 64 assertions")
  }
  let seen : Map[String, Bool] = Map([])
  for a in assertions {
    if seen.contains(a.id) {
      raise Invalid("duplicate assertion id")
    }
    seen[a.id] = true
  }
  let e = Engine::new(max_nodes)
  let c = e.compile(self)
  let results = []
  for a in assertions {
    let bad = if a.expected == Allow { e.not(c.allowed) } else { c.allowed }
    let counterexample = e.witness(e.both(e.predicate(a.scope.rule), bad))
    let actual = match counterexample {
      None => None
      Some(p) => {
        let d = self.evaluate(p)
        if d.action == a.expected || !a.scope.contains(p) {
          raise Invalid("internal assertion replay mismatch")
        }
        Some(d)
      }
    }
    results.push({
      id: a.id,
      passed: counterexample is None,
      counterexample,
      actual,
    })
  }
  results
}

///|
pub fn parse_assertions(text : String) -> Array[Assertion] raise PolicyError {
  if text.length() > 32768 {
    raise Invalid("assertions exceed 32 KiB")
  }
  let result = []
  for i, line in text.split("\n").to_array() {
    if i >= 128 || line.length() > 512 {
      raise Invalid("assertion file line limit exceeded")
    }
    let line = line.trim().to_owned()
    if line == "" || line.has_prefix("#") {
      continue
    }
    let words = line
      .split(" ")
      .filter(s => s.length() > 0)
      .map(s => s.to_owned())
      .to_array()
    try {
      match words {
        ["assert", id, action, p, s, d, sp, dp] => {
          if result.length() >= 64 {
            raise Invalid("at most 64 assertions")
          }
          result.push(
            Assertion::new(
              id,
              parse_action(action),
              Scope::new(
                parse_protocol(p),
                s,
                d,
                Ports::parse(sp),
                Ports::parse(dp),
              ),
            ),
          )
        }
        _ =>
          raise Invalid(
            "expected assert id allow|deny protocol source destination source-ports destination-ports",
          )
      }
    } catch {
      Invalid(e) => raise Invalid("line \{i+1}: \{e}")
      e => raise e
    }
  }
  if result.length() == 0 {
    raise Invalid("empty assertion suite")
  }
  result
}
