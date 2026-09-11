///|
pub(all) enum Coverage {
  Reachable
  Partial
  Shadowed
} derive(Eq, Debug)

///|
pub(all) struct RuleAudit {
  rule_id : String
  coverage : Coverage
  reachable_witness : Packet?
  blocked_witness : Packet?
  blocked_by : String?
} derive(Eq, Debug)

///|
/// Coverage subtracts the union of all earlier rules, regardless of their action.
pub fn Policy::audit(
  self : Policy,
  max_nodes? : Int = 100000,
) -> Array[RuleAudit] raise PolicyError {
  let e = Engine::new(max_nodes)
  let c = e.compile(self)
  let reports = []
  for i, rule in self.rules {
    let active = c.effective[i]
    let blocked = e.both(c.predicates[i], e.not(active))
    let reachable_witness = e.witness(active)
    let blocked_witness = e.witness(blocked)
    if reachable_witness is Some(p) {
      if self.evaluate(p).rule_id != Some(rule.id) {
        raise Invalid("internal reachability witness mismatch")
      }
    }
    let blocked_by = match blocked_witness {
      None => None
      Some(p) => {
        let d = self.evaluate(p)
        if !rule.matches(p) ||
          d.rule_id is None ||
          d.rule_id == Some(rule.id) ||
          d.tested_rules > i {
          raise Invalid("internal shadow witness mismatch")
        }
        d.rule_id
      }
    }
    let coverage = if reachable_witness is None {
      Shadowed
    } else if blocked_witness is Some(_) {
      Partial
    } else {
      Reachable
    }
    reports.push({
      rule_id: rule.id,
      coverage,
      reachable_witness,
      blocked_witness,
      blocked_by,
    })
  }
  reports
}
