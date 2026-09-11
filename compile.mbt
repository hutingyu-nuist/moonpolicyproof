///|
priv struct Compiled {
  allowed : @bdd.Bdd
  effective : Array[@bdd.Bdd]
  predicates : Array[@bdd.Bdd]
}

///|
fn Engine::compile(
  self : Engine,
  policy : Policy,
) -> Compiled raise PolicyError {
  let mut remaining = self.manager.true_bdd()
  let mut allowed = self.manager.false_bdd()
  let effective = []
  let predicates = []
  for rule in policy.rules {
    let predicate = self.predicate(rule)
    let hit = self.both(remaining, predicate)
    predicates.push(predicate)
    effective.push(hit)
    if rule.action == Allow {
      allowed = self.or(allowed, hit)
    }
    remaining = self.both(remaining, self.not(predicate))
  }
  if policy.default_action == Allow {
    allowed = self.or(allowed, remaining)
  }
  { allowed, effective, predicates }
}

///|
/// Finds a packet receiving a requested decision, not merely matching a rule.
pub fn Policy::find(
  self : Policy,
  action : Action,
  max_nodes? : Int = 100000,
) -> Packet? raise PolicyError {
  let e = Engine::new(max_nodes)
  let c = e.compile(self)
  let root = if action == Allow { c.allowed } else { e.not(c.allowed) }
  let packet = e.witness(root)
  if packet is Some(p) {
    if self.evaluate(p).action != action {
      raise Internal("internal decision witness mismatch")
    }
  }
  packet
}
