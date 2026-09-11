///|
/// Encode independently from witness decoding: separate UInt source fields and shifts.
fn assignment(packet : Packet) -> Array[(String, Bool)] {
  let values : Array[Bool] = []
  for value in [packet.source.value(), packet.destination.value()] {
    for shift = 31; shift >= 0; shift = shift - 1 {
      values.push(((value >> shift) & 1U) == 1U)
    }
  }
  values.push(packet.protocol == Udp)
  for value in [packet.source_port, packet.destination_port] {
    for shift = 15; shift >= 0; shift = shift - 1 {
      values.push(((value >> shift) & 1) == 1)
    }
  }
  values.mapi((i, b) => ("b" + i.to_string(), b))
}

///|
fn generated_policy(seed : Int) -> Policy raise PolicyError {
  let rules = []
  for i = 0; i < 5; i = i + 1 {
    let src = if (seed + i) % 3 == 0 {
      "192.0.2.0/30"
    } else if (seed + i) % 3 == 1 {
      "192.0.2.0/31"
    } else {
      "192.0.2.2/31"
    }
    let dst = if (seed + i) % 2 == 0 {
      "198.51.100.0/30"
    } else {
      "198.51.100.1/32"
    }
    let proto = match (seed + i) % 3 {
      0 => None
      1 => Some(Tcp)
      _ => Some(Udp)
    }
    rules.push(
      Rule::new(
        "r" + i.to_string(),
        if (seed + i) % 2 == 0 {
          Allow
        } else {
          Deny
        },
        proto,
        src,
        dst,
        Ports::new(i % 4, 3),
        Ports::new(0, (seed + i) % 4),
      ),
    )
  }
  Policy::new(rules, if seed % 2 == 0 { Allow } else { Deny })
}

///|
test "generated policies agree with independent evaluator over reduced universe" {
  let packets = []
  for s = 0; s < 4; s = s + 1 {
    for d = 0; d < 4; d = d + 1 {
      for proto in [Tcp, Udp] {
        for sp = 0; sp < 4; sp = sp + 1 {
          for dp = 0; dp < 4; dp = dp + 1 {
            packets.push(
              Packet::new(
                "192.0.2." + s.to_string(),
                "198.51.100." + d.to_string(),
                proto,
                sp,
                dp,
              ),
            )
          }
        }
      }
    }
  }
  assert_eq(packets.length(), 512)
  for seed = 0; seed < 12; seed = seed + 1 {
    let policy = generated_policy(seed)
    let e = Engine::new(100000)
    let c = e.compile(policy)
    for packet in packets {
      let decision = policy.evaluate(packet)
      assert_eq(
        bdd_value(e.manager.evaluate(c.allowed, assignment(packet))),
        decision.action == Allow,
      )
      for i, rule in policy.rules {
        assert_eq(
          bdd_value(e.manager.evaluate(c.effective[i], assignment(packet))),
          decision.rule_id == Some(rule.id),
        )
      }
    }
  }
}

///|
test "scoped diff emptiness matches exhaustive oracle in both directions" {
  let scope = Scope::parse("any 192.0.2.0/30 198.51.100.0/30 0-3 0-3")
  for seed = 0; seed < 12; seed = seed + 1 {
    let before = generated_policy(seed)
    let after = generated_policy(seed + 1)
    let mut has_allow = false
    let mut has_deny = false
    for s = 0; s < 4; s = s + 1 {
      for d = 0; d < 4; d = d + 1 {
        for proto in [Tcp, Udp] {
          for sp = 0; sp < 4; sp = sp + 1 {
            for dp = 0; dp < 4; dp = dp + 1 {
              let p = Packet::new(
                "192.0.2." + s.to_string(),
                "198.51.100." + d.to_string(),
                proto,
                sp,
                dp,
              )
              let a = before.evaluate(p).action
              let b = after.evaluate(p).action
              has_allow = has_allow || (a == Deny && b == Allow)
              has_deny = has_deny || (a == Allow && b == Deny)
            }
          }
        }
      }
    }
    let report = compare_scoped(before, after, scope)
    assert_eq(report.allowed_witness() is Some(_), has_allow)
    assert_eq(report.denied_witness() is Some(_), has_deny)
  }
}
