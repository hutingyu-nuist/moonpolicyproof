///|
/// A rectangular query domain; has no action and cannot reorder a policy.
pub struct Scope {
  rule : Rule
} derive(Eq, Debug)

///|
pub fn Scope::new(
  protocol : Protocol?,
  source : String,
  destination : String,
  source_ports : Ports,
  destination_ports : Ports,
) -> Scope raise PolicyError {
  {
    rule: Rule::new(
      "scope",
      Allow,
      protocol,
      source,
      destination,
      source_ports,
      destination_ports,
    ),
  }
}

///|
pub fn Scope::parse(text : String) -> Scope raise PolicyError {
  if text.length() > 256 {
    raise Invalid("scope too long")
  }
  let words = text
    .trim()
    .to_owned()
    .split(" ")
    .filter(s => s.length() > 0)
    .map(s => s.to_owned())
    .to_array()
  match words {
    [p, s, d, sp, dp] =>
      Scope::new(parse_protocol(p), s, d, Ports::parse(sp), Ports::parse(dp))
    _ =>
      raise Invalid(
        "scope requires protocol source-CIDR destination-CIDR source-ports destination-ports",
      )
  }
}

///|
pub fn Scope::contains(self : Scope, packet : Packet) -> Bool {
  self.rule.matches(packet)
}

///|
pub fn Scope::render(self : Scope) -> String {
  let r = self.rule
  let proto = match r.protocol {
    Some(p) => p.render()
    None => "any"
  }
  "\{proto} \{r.source.to_string()} \{r.destination.to_string()} \{r.source_ports.render()} \{r.destination_ports.render()}"
}

///|
pub fn compare_scoped(
  before : Policy,
  after : Policy,
  scope : Scope,
  max_nodes? : Int = 100000,
) -> DiffReport raise PolicyError {
  let e = Engine::new(max_nodes)
  let old = e.compile(before).allowed
  let next = e.compile(after).allowed
  let domain = e.predicate(scope.rule)
  let newly_allowed = replay_change(
    e.witness(e.both(domain, e.both(e.not(old), next))),
    before,
    after,
    Deny,
    Allow,
  )
  let newly_denied = replay_change(
    e.witness(e.both(domain, e.both(old, e.not(next)))),
    before,
    after,
    Allow,
    Deny,
  )
  for w in [newly_allowed, newly_denied] {
    if w is Some(w) {
      if !scope.contains(w.packet) {
        raise Internal("internal scoped witness mismatch")
      }
    }
  }
  {
    newly_allowed,
    newly_denied,
    retained_nodes: e.manager.retained_node_count(),
  }
}

///|
pub fn Policy::find_scoped(
  self : Policy,
  action : Action,
  scope : Scope,
  max_nodes? : Int = 100000,
) -> Packet? raise PolicyError {
  let e = Engine::new(max_nodes)
  let c = e.compile(self)
  let root = e.both(
    e.predicate(scope.rule),
    if action == Allow {
      c.allowed
    } else {
      e.not(c.allowed)
    },
  )
  let w = e.witness(root)
  if w is Some(p) {
    if !scope.contains(p) || self.evaluate(p).action != action {
      raise Internal("internal scoped query mismatch")
    }
  }
  w
}
