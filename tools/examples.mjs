import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
const cli=process.env.MOONPOLICYPROOF_CLI || '_build/js/debug/build/cmd/main/main.js';
function run(args,code){const r=spawnSync(process.execPath,[cli,...args],{encoding:'utf8',timeout:20000});assert.equal(r.status,code,r.stderr||r.stdout);return JSON.parse(r.stdout);}
const one='examples/01-change/',two='examples/02-shadow/',three='examples/03-regression/';
let r=run(['diff',one+'before.policy',one+'after.policy'],1);
assert.equal(r.result.newly_allowed.before.action,'deny');assert.equal(r.result.newly_allowed.after.action,'allow');assert.equal(r.result.newly_denied,null);
r=run(['diff',one+'before.policy',one+'after.policy',one+'business.scope'],0);assert.equal(r.result.equivalent,true);assert.notEqual(r.scope,null);
r=run(['audit',two+'policy.policy'],0);assert.deepEqual(r.rules.map(x=>x.coverage),['reachable','reachable','shadowed','partial']);
r=run(['check',three+'policy.policy',three+'good.assertions'],0);assert.equal(r.passed,true);
r=run(['check',three+'policy.policy',three+'bad.assertions'],1);assert.equal(r.assertions[0].actual.action,'deny');
console.log('Three executable scenarios passed: scoped change review; union shadow audit; positive and negative CI assertions.');
