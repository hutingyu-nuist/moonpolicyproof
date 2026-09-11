///|
/// Stable string ABI shared by browser worker and Node consumers.
pub fn analyze(request : String) -> String {
  let (code, body) = @proof.handle_request(request)
  ({ "exit_code": code, "body": body } : Json).stringify()
}
