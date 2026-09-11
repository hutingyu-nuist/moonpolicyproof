///|
/// Concrete evaluation intentionally does not use any BDD machinery.
pub fn Rule::matches(self : Rule, packet : Packet) -> Bool {
  self.source.contains_ip(packet.source) &&
  self.destination.contains_ip(packet.destination) &&
  (self.protocol is None || self.protocol == Some(packet.protocol)) &&
  self.source_ports.contains(packet.source_port) &&
  self.destination_ports.contains(packet.destination_port)
}

///|
pub(all) struct Decision {
  action : Action
  rule_id : String?
  tested_rules : Int
} derive(Eq, Debug)

///|
pub fn Policy::evaluate(self : Policy, packet : Packet) -> Decision {
  for i, rule in self.rules {
    if rule.matches(packet) {
      return {
        action: rule.action,
        rule_id: Some(rule.id),
        tested_rules: i + 1,
      }
    }
  }
  {
    action: self.default_action,
    rule_id: None,
    tested_rules: self.rules.length(),
  }
}
