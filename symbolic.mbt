///|
/// One analysis owns one manager; BDD handles never escape this package.
priv struct Engine {
  manager : @bdd.Manager
}

///|
fn Engine::new(max_nodes : Int) -> Engine raise PolicyError {
  if max_nodes < 2 || max_nodes > 200000 {
    raise Invalid("node budget must be 2..200000")
  }
  let names : Array[String] = []
  for i = 0; i < 97; i = i + 1 {
    names.push("b" + i.to_string())
  }
  let budget = {
    ..@bdd.ResourceBudget::default(),
    max_nodes,
    max_cache_entries: max_nodes,
    max_work: 1000000,
    max_depth: 128,
  }
  { manager: bdd_value(@bdd.Manager::new(names, budget)) }
}

///|
fn Engine::both(
  self : Engine,
  a : @bdd.Bdd,
  b : @bdd.Bdd,
) -> @bdd.Bdd raise PolicyError {
  bdd_value(self.manager.and_bdd(a, b))
}

///|
fn Engine::or(
  self : Engine,
  a : @bdd.Bdd,
  b : @bdd.Bdd,
) -> @bdd.Bdd raise PolicyError {
  bdd_value(self.manager.or_bdd(a, b))
}

///|
fn Engine::not(self : Engine, a : @bdd.Bdd) -> @bdd.Bdd raise PolicyError {
  bdd_value(self.manager.not_bdd(a))
}

///|
fn Engine::bit(self : Engine, index : Int) -> @bdd.Bdd raise PolicyError {
  bdd_value(self.manager.variable("b" + index.to_string()))
}

///|
fn Engine::cidr(
  self : Engine,
  block : @cidr.CidrBlock,
  offset : Int,
) -> @bdd.Bdd raise PolicyError {
  let mut root = self.manager.true_bdd()
  let value = block.network().value()
  for i = 0; i < block.prefix(); i = i + 1 {
    let b = self.bit(offset + i)
    let literal = if ((value >> (31 - i)) & 1U) == 1U { b } else { self.not(b) }
    root = self.both(root, literal)
  }
  root
}

///|
/// MSB-first comparator, built bottom-up; never enumerates the port space.
fn Engine::at_most(
  self : Engine,
  offset : Int,
  upper : Int,
) -> @bdd.Bdd raise PolicyError {
  let mut root = self.manager.true_bdd()
  for i = 15; i >= 0; i = i - 1 {
    let b = self.bit(offset + i)
    root = if ((upper >> (15 - i)) & 1) == 1 {
      self.or(self.not(b), root)
    } else {
      self.both(self.not(b), root)
    }
  }
  root
}

///|
fn Engine::ports(
  self : Engine,
  ports : Ports,
  offset : Int,
) -> @bdd.Bdd raise PolicyError {
  let hi = self.at_most(offset, ports.high)
  if ports.low == 0 {
    hi
  } else {
    self.both(hi, self.not(self.at_most(offset, ports.low - 1)))
  }
}

///|
fn Engine::predicate(self : Engine, rule : Rule) -> @bdd.Bdd raise PolicyError {
  let mut root = self.both(
    self.cidr(rule.source, 0),
    self.cidr(rule.destination, 32),
  )
  match rule.protocol {
    Some(Tcp) => root = self.both(root, self.not(self.bit(64)))
    Some(Udp) => root = self.both(root, self.bit(64))
    None => ()
  }
  root = self.both(root, self.ports(rule.source_ports, 65))
  self.both(root, self.ports(rule.destination_ports, 81))
}

///|
fn Engine::witness(self : Engine, root : @bdd.Bdd) -> Packet? raise PolicyError {
  match bdd_value(self.manager.sat_one(root)) {
    None => None
    Some(model) => {
      let bits : Map[String, Bool] = Map(model.values)
      let mut src = 0U
      let mut dst = 0U
      let mut sp = 0
      let mut dp = 0
      for i = 0; i < 32; i = i + 1 {
        src = (src << 1) |
          (if bits.get("b" + i.to_string()).unwrap_or(false) { 1U } else { 0U })
        dst = (dst << 1) |
          (if bits.get("b" + (i + 32).to_string()).unwrap_or(false) {
            1U
          } else {
            0U
          })
      }
      for i = 0; i < 16; i = i + 1 {
        sp = sp * 2 +
          (if bits.get("b" + (65 + i).to_string()).unwrap_or(false) {
            1
          } else {
            0
          })
        dp = dp * 2 +
          (if bits.get("b" + (81 + i).to_string()).unwrap_or(false) {
            1
          } else {
            0
          })
      }
      Some({
        source: @cidr.IPv4::new(src),
        destination: @cidr.IPv4::new(dst),
        protocol: if bits.get("b64").unwrap_or(false) {
          Udp
        } else {
          Tcp
        },
        source_port: sp,
        destination_port: dp,
      })
    }
  }
}

///|
/// Produces one matching packet, then independently validates it.
pub fn Rule::witness(
  self : Rule,
  max_nodes? : Int = 100000,
) -> Packet raise PolicyError {
  let e = Engine::new(max_nodes)
  match e.witness(e.predicate(self)) {
    Some(p) => {
      if !self.matches(p) {
        raise Invalid("internal predicate witness mismatch")
      }
      p
    }
    None => raise Invalid("internal empty rule predicate")
  }
}
