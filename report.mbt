///|
pub fn Packet::to_json(self : Packet) -> Json {
  {
    "source": self.source.to_dotted(),
    "destination": self.destination.to_dotted(),
    "protocol": self.protocol.render(),
    "source_port": self.source_port,
    "destination_port": self.destination_port,
  }
}

///|
pub fn Decision::to_json(self : Decision) -> Json {
  {
    "action": self.action.render(),
    "rule_id": match self.rule_id {
      Some(x) => Json::string(x)
      None => Json::null()
    },
    "tested_rules": self.tested_rules,
  }
}

///|
fn change_json(w : ChangeWitness?) -> Json {
  match w {
    None => Json::null()
    Some(w) =>
      {
        "packet": w.packet.to_json(),
        "before": w.before.to_json(),
        "after": w.after.to_json(),
        "replayed": true,
      }
  }
}

///|
pub fn DiffReport::to_json(self : DiffReport) -> Json {
  {
    "schema": "moonpolicyproof.diff.v1",
    "model": "ipv4-tcp-udp-stateless-first-match",
    "equivalent": self.equivalent(),
    "newly_allowed": change_json(self.newly_allowed),
    "newly_denied": change_json(self.newly_denied),
    "retained_nodes": self.retained_nodes,
  }
}

///|
pub fn Coverage::render(self : Coverage) -> String {
  match self {
    Reachable => "reachable"
    Partial => "partial"
    Shadowed => "shadowed"
  }
}

///|
fn optional_packet(p : Packet?) -> Json {
  match p {
    None => Json::null()
    Some(p) => p.to_json()
  }
}

///|
pub fn audit_json(reports : Array[RuleAudit]) -> Json {
  {
    "schema": "moonpolicyproof.audit.v1",
    "rules": Json::array(
      reports.map(r => {
        "rule_id": r.rule_id,
        "coverage": r.coverage.render(),
        "reachable_witness": optional_packet(r.reachable_witness),
        "blocked_witness": optional_packet(r.blocked_witness),
        "blocked_by": match r.blocked_by {
          None => Json::null()
          Some(id) => Json::string(id)
        },
      }),
    ),
  }
}

///|
pub fn assertions_json(results : Array[AssertionResult]) -> Json {
  {
    "schema": "moonpolicyproof.assertions.v1",
    "passed": results.iter().all(r => r.passed),
    "assertions": Json::array(
      results.map(r => {
        "id": r.id,
        "passed": r.passed,
        "counterexample": optional_packet(r.counterexample),
        "actual": match r.actual {
          None => Json::null()
          Some(d) => d.to_json()
        },
      }),
    ),
  }
}

///|
pub fn DiffReport::render(self : DiffReport) -> String {
  let lines = [
    "model: IPv4 TCP/UDP stateless first-match",
    "equivalent: " + self.equivalent().to_string(),
  ]
  for
    entry in [
      ("newly allowed", self.newly_allowed),
      ("newly denied", self.newly_denied),
    ] {
    let (label, w) = entry
    match w {
      None => lines.push(label + ": none")
      Some(w) =>
        lines.push(
          label +
          ": " +
          w.packet.to_json().stringify() +
          " (independently replayed)",
        )
    }
  }
  lines.join("\n") + "\n"
}
