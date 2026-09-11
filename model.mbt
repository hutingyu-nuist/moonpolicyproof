///|
pub(all) enum Action {
  Allow
  Deny
} derive(Eq, Debug)

///|
pub(all) enum Protocol {
  Tcp
  Udp
} derive(Eq, Debug)

///|
pub struct Packet {
  source : @cidr.IPv4
  destination : @cidr.IPv4
  protocol : Protocol
  source_port : Int
  destination_port : Int
} derive(Eq, Debug)

///|
pub fn Packet::new(
  source : String,
  destination : String,
  protocol : Protocol,
  source_port : Int,
  destination_port : Int,
) -> Packet raise PolicyError {
  if source.length() > 15 || destination.length() > 15 {
    raise Invalid("IPv4 text too long")
  }
  let source = match @cidr.IPv4::parse(source) {
    Ok(x) => x
    Err(e) => raise Invalid(e)
  }
  let destination = match @cidr.IPv4::parse(destination) {
    Ok(x) => x
    Err(e) => raise Invalid(e)
  }
  ignore(Ports::new(source_port, source_port))
  ignore(Ports::new(destination_port, destination_port))
  { source, destination, protocol, source_port, destination_port }
}

///|
pub fn Packet::fields(self : Packet) -> (String, String, Protocol, Int, Int) {
  (
    self.source.to_dotted(),
    self.destination.to_dotted(),
    self.protocol,
    self.source_port,
    self.destination_port,
  )
}

///|
pub struct Rule {
  id : String
  action : Action
  protocol : Protocol?
  source : @cidr.CidrBlock
  destination : @cidr.CidrBlock
  source_ports : Ports
  destination_ports : Ports
} derive(Eq, Debug)

///|
pub fn Rule::new(
  id : String,
  action : Action,
  protocol : Protocol?,
  source : String,
  destination : String,
  source_ports : Ports,
  destination_ports : Ports,
) -> Rule raise PolicyError {
  if id.length() == 0 || id.length() > 64 {
    raise Invalid("rule id must contain 1..64 characters")
  }
  for c in id.iter() {
    if !((c >= 'a' && c <= 'z') ||
      (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9') ||
      c == '_' ||
      c == '-') {
      raise Invalid("rule id must be ASCII alphanumeric, _ or -")
    }
  }
  if source.length() > 18 || destination.length() > 18 {
    raise Invalid("CIDR text too long")
  }
  {
    id,
    action,
    protocol,
    source: cidr_value(source),
    destination: cidr_value(destination),
    source_ports,
    destination_ports,
  }
}

///|
pub fn Rule::name(self : Rule) -> String {
  self.id
}

///|
pub struct Policy {
  rules : Array[Rule]
  default_action : Action
} derive(Eq, Debug)

///|
pub fn Policy::new(
  rules : Array[Rule],
  default_action : Action,
) -> Policy raise PolicyError {
  if rules.length() > 256 {
    raise Invalid("at most 256 rules")
  }
  let seen : Map[String, Bool] = Map([])
  for rule in rules {
    if seen.contains(rule.id) {
      raise Invalid("duplicate rule id: " + rule.id)
    }
    seen[rule.id] = true
  }
  { rules: rules.copy(), default_action }
}

///|
pub fn Policy::rule_count(self : Policy) -> Int {
  self.rules.length()
}
