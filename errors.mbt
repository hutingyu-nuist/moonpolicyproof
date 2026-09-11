///|
pub suberror PolicyError {
  Invalid(String)
  Resource(String)
} derive(Debug)

///|
fn[T] bdd_value(r : Result[T, @bdd.BddError]) -> T raise PolicyError {
  match r {
    Ok(x) => x
    Err(e) => raise Resource(@debug.to_string(e))
  }
}

///|
fn cidr_value(s : String) -> @cidr.CidrBlock raise PolicyError {
  match @cidr.CidrBlock::parse(s) {
    Ok(x) => x
    Err(e) => raise Invalid(e)
  }
}
