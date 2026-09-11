///|
/// Inclusive transport port interval. Construction rejects invalid endpoints.
pub struct Ports {
  low : Int
  high : Int
} derive(Eq, Debug)

///|
pub fn Ports::new(low : Int, high : Int) -> Ports raise PolicyError {
  if low < 0 || high > 65535 || low > high {
    raise Invalid("port interval must satisfy 0 <= low <= high <= 65535")
  }
  { low, high }
}

///|
pub fn Ports::any() -> Ports {
  { low: 0, high: 65535 }
}

///|
pub fn Ports::contains(self : Ports, port : Int) -> Bool {
  self.low <= port && port <= self.high
}

///|
pub fn Ports::bounds(self : Ports) -> (Int, Int) {
  (self.low, self.high)
}

///|
fn decimal(s : String) -> Int raise PolicyError {
  if s.length() == 0 || s.length() > 5 {
    raise Invalid("invalid port number")
  }
  let mut n = 0
  for c in s.iter() {
    if c < '0' || c > '9' {
      raise Invalid("expected decimal digits")
    }
    n = n * 10 + c.to_int() - 48
  }
  n
}

///|
pub fn Ports::parse(s : String) -> Ports raise PolicyError {
  if s == "*" {
    return Ports::any()
  }
  let parts = s.split("-").map(x => x.to_owned()).to_array()
  match parts {
    [a] => {
      let n = decimal(a)
      Ports::new(n, n)
    }
    [a, b] => Ports::new(decimal(a), decimal(b))
    _ => raise Invalid("expected *, port or low-high")
  }
}

///|
pub fn Ports::render(self : Ports) -> String {
  if self == Ports::any() {
    "*"
  } else if self.low == self.high {
    self.low.to_string()
  } else {
    "\{self.low}-\{self.high}"
  }
}
