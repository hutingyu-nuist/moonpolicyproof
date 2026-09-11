import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const cli=process.env.MOONPOLICYPROOF_CLI || '_build/js/debug/build/cmd/main/main.js';
const run=(args)=>spawnSync(process.execPath,[cli,...args],{encoding:'utf8',timeout:20000});
const temp=mkdtempSync(join(tmpdir(),'moonpolicyproof-'));
try {
 const before=join(temp,'before.policy'),after=join(temp,'after.policy');
 writeFileSync(before,'moonpolicyproof 1\ndefault deny\n');
 writeFileSync(after,'moonpolicyproof 1\ndefault allow\n');
 let r=run(['diff',before,after]); assert.equal(r.status,1,r.stderr); assert.equal(JSON.parse(r.stdout).result.equivalent,false);
 r=run(['diff',before,before]); assert.equal(r.status,0,r.stderr);
 for(const args of [['diff',before],['audit',temp],['audit',join(temp,'missing')],['help','extra']]) {r=run(args);assert.equal(r.status,2,r.stderr);assert.equal(JSON.parse(r.stdout).category,'invalid');}
 const invalid=join(temp,'bad');writeFileSync(invalid,Buffer.from([0xff,0xfe]));assert.equal(run(['audit',invalid]).status,2);
 writeFileSync(invalid,'x'.repeat(131073));assert.equal(run(['audit',invalid]).status,2);
 console.log('CLI smoke: semantic exit codes, argument errors, directories, missing/oversize/invalid-UTF8 files passed');
} finally {rmSync(temp,{recursive:true,force:true});}
