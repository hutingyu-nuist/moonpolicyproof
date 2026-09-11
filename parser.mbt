///|
fn parse_action(s : String) -> Action raise PolicyError {
  match s {
    "allow" => Allow
    "deny" => Deny
    _ => raise Invalid("expected allow or deny")
  }
}

///|
fn parse_protocol(s : String) -> Protocol? raise PolicyError {
  match s {
    "tcp" => Some(Tcp)
    "udp" => Some(Udp)
    "any" => None
    _ => raise Invalid("expected tcp, udp or any")
  }
}

///|
/// Strict ASCII, versioned, bounded DSL. Comments and blank lines are allowed.
pub fn Policy::parse(text : String) -> Policy raise PolicyError {
  if text.length() > 131072 {
    raise Invalid("policy exceeds 128 KiB ASCII limit")
  }
  for c in text.iter() {
    if c.to_int() > 127 ||
      (c.to_int() < 32 && c != '\n' && c != '\r' && c != '\t') {
      raise Invalid("policy must be ASCII text")
    }
  }
  let mut header = false
  let mut default_action : Action? = None
  let rules : Array[Rule] = []
  for i, line in text.split("\n").to_array() {
    if i >= 1024 {
      raise Invalid("policy exceeds 1024 lines")
    }
    if line.length() > 512 {
      raise Invalid("line \{i+1}: exceeds 512 characters")
    }
    let line = line.trim().to_owned()
    if line == "" || line.has_prefix("#") {
      continue
    }
    let words = line
      .replace_all(old="\t", new=" ")
      .split(" ")
      .filter(s => s.length() > 0)
      .map(s => s.to_owned())
      .to_array()
    try {
      if !header {
        if words != ["moonpolicyproof", "1"] {
          raise Invalid("expected moonpolicyproof 1 header")
        }
        header = true
        continue
      }
      match words {
        ["default", action] => {
          if default_action is Some(_) || rules.length() > 0 {
            raise Invalid("default must occur once before rules")
          }
          default_action = Some(parse_action(action))
        }
        ["rule", id, action, proto, src, dst, sp, dp] => {
          if default_action is None {
            raise Invalid("default required before rules")
          }
          if rules.length() >= 256 {
            raise Invalid("at most 256 rules")
          }
          rules.push(
            Rule::new(
              id,
              parse_action(action),
              parse_protocol(proto),
              src,
              dst,
              Ports::parse(sp),
              Ports::parse(dp),
            ),
          )
        }
        _ => raise Invalid("unknown directive or wrong field count")
      }
    } catch {
      Invalid(e) => raise Invalid("line \{i+1}: \{e}")
      e => raise e
    }
  }
  if !header {
    raise Invalid("missing version header")
  }
  match default_action {
    Some(a) => Policy::new(rules, a)
    None => raise Invalid("missing default action")
  }
}
