///|
pub fn Action::render(self : Action) -> String {
  match self {
    Allow => "allow"
    Deny => "deny"
  }
}

///|
pub fn Protocol::render(self : Protocol) -> String {
  match self {
    Tcp => "tcp"
    Udp => "udp"
  }
}

///|
pub fn Rule::render(self : Rule) -> String {
  let proto = match self.protocol {
    Some(p) => p.render()
    None => "any"
  }
  "rule \{self.id} \{self.action.render()} \{proto} \{self.source.to_string()} \{self.destination.to_string()} \{self.source_ports.render()} \{self.destination_ports.render()}"
}

///|
pub fn Policy::render(self : Policy) -> String {
  let lines = ["moonpolicyproof 1", "default " + self.default_action.render()]
  for r in self.rules {
    lines.push(r.render())
  }
  lines.join("\n") + "\n"
}
