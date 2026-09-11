import {spawnSync} from 'node:child_process';
function run(exe,args){console.log('> '+exe+' '+args.join(' '));const r=spawnSync(exe,args,{stdio:'inherit',timeout:240000});if(r.error)throw r.error;if(r.status!==0)process.exit(r.status||1);}
run('moon',['version','--all']);
run('moon',['fmt','--check']);
const targets=['wasm-gc','wasm','js'];if(process.argv.includes('--native'))targets.push('native');
for(const target of targets){for(const step of ['check','build','test'])run('moon',[step,'--target',target,'--deny-warn']);}
if(!targets.includes('native')){run('moon',['check','--target','native','--deny-warn']);console.log('Native execution NOT run locally; CI uses --native and a C toolchain.');}
for(const tool of ['cli-smoke','examples','bridge-smoke'])run(process.execPath,['tools/'+tool+'.mjs']);
run('moon',['info']);
run('git',['diff','--exit-code','--','*.mbti']);
console.log('Verification complete; no MoonCakes publication is performed.');
