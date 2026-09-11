///|
/// Filesystem and process plumbing only; all policy logic lives in the pure core.
extern "js" fn read_request() -> String =
  #| () => {
  #|   const fs = require('node:fs');
  #|   const args = process.argv.slice(2);
  #|   if (args[0] === '--') args.shift();
  #|   const read = name => {
  #|     const fd = fs.openSync(name, 'r');
  #|     try {
  #|       if (!fs.fstatSync(fd).isFile()) throw Error('input must be a regular file');
  #|       const buf = Buffer.alloc(131073);
  #|       let used = 0;
  #|       while (used < buf.length) { const n = fs.readSync(fd, buf, used, buf.length-used, null); if (!n) break; used += n; }
  #|       if (used > 131072) throw Error('input exceeds 128 KiB');
  #|       return new TextDecoder('utf-8', {fatal:true}).decode(buf.subarray(0,used));
  #|     } finally { fs.closeSync(fd); }
  #|   };
  #|   try {
  #|     const command = args[0] || 'help';
  #|     const size = {help:[0,1],diff:[3,4],audit:[2],format:[2],check:[3]}[command];
  #|     if (!size || !size.includes(args.length)) throw Error('invalid arguments; use help');
  #|     const req = {command};
  #|     if (command === 'diff') { req.before=read(args[1]); req.after=read(args[2]); if(args.length===4) req.scope=read(args[3]).trim(); }
  #|     else if (command !== 'help') { req.policy=read(args[1]); if(command==='check') req.assertions=read(args[2]); }
  #|     return JSON.stringify(req);
  #|   } catch(e) {
  #|     process.stderr.write('MoonPolicyProof input error: '+e.message+'\n');
  #|     return '{}';
  #|   }
  #| }

///|
extern "js" fn set_exit(code : Int) -> Unit =
  #| code => { process.exitCode = code; }

///|
fn main {
  let (code, body) = @proof.handle_request(read_request())
  println(body)
  set_exit(code)
}
