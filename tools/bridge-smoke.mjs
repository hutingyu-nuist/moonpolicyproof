import assert from 'node:assert/strict';
import {analyze} from '../_build/js/debug/build/browser/browser.js';
const r=JSON.parse(analyze(JSON.stringify({command:'diff',before:'moonpolicyproof 1\ndefault deny',after:'moonpolicyproof 1\ndefault allow'})));
assert.equal(r.exit_code,1);assert.equal(JSON.parse(r.body).result.newly_allowed.replayed,true);
assert.equal(JSON.parse(analyze('{bad')).exit_code,2);
console.log('Browser string ABI: actual MoonBit output and invalid-input path passed');
