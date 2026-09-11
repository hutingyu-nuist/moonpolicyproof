///|
pub(all) struct ChangeWitness {
  packet : Packet
  before : Decision
  after : Decision
} derive(Eq, Debug)

///|
pub struct DiffReport {
  newly_allowed : ChangeWitness?
  newly_denied : ChangeWitness?
  retained_nodes : Int
} derive(Eq, Debug)

///|
pub fn DiffReport::equivalent(self : DiffReport) -> Bool {
  self.newly_allowed is None && self.newly_denied is None
}

///|
pub fn DiffReport::allowed_witness(self : DiffReport) -> ChangeWitness? {
  self.newly_allowed
}

///|
pub fn DiffReport::denied_witness(self : DiffReport) -> ChangeWitness? {
  self.newly_denied
}

///|
pub fn DiffReport::node_count(self : DiffReport) -> Int {
  self.retained_nodes
}

///|
fn replay_change(
  packet : Packet?,
  before : Policy,
  after : Policy,
  expected_before : Action,
  expected_after : Action,
) -> ChangeWitness? raise PolicyError {
  match packet {
    None => None
    Some(packet) => {
      let old = before.evaluate(packet)
      let next = after.evaluate(packet)
      if old.action != expected_before || next.action != expected_after {
        raise Invalid("internal semantic witness replay mismatch")
      }
      Some({ packet, before: old, after: next })
    }
  }
}

///|
/// Exact equality over the finite IPv4/TCP/UDP model, not device equivalence.
pub fn compare(
  before : Policy,
  after : Policy,
  max_nodes? : Int = 100000,
) -> DiffReport raise PolicyError {
  let e = Engine::new(max_nodes)
  let old = e.compile(before).allowed
  let next = e.compile(after).allowed
  let newly_allowed = replay_change(
    e.witness(e.both(e.not(old), next)),
    before,
    after,
    Deny,
    Allow,
  )
  let newly_denied = replay_change(
    e.witness(e.both(old, e.not(next))),
    before,
    after,
    Allow,
    Deny,
  )
  {
    newly_allowed,
    newly_denied,
    retained_nodes: e.manager.retained_node_count(),
  }
}
