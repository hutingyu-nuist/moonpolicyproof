///|
/// MoonBit 0.10.4 core marks the depth label as migrating, but exposes no replacement.
/// Keep suppression at this single call: removing the limit would weaken the boundary.
#warnings("-deprecated")
fn parse_request_json(text : String) -> Json raise @json.ParseError {
  @json.parse(text, max_nesting_depth=8)
}
