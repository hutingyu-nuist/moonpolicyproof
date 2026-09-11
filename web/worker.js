import {analyze} from '../_build/js/debug/build/browser/browser.js';
self.onmessage=({data})=>{
 try {const envelope=JSON.parse(analyze(JSON.stringify(data)));self.postMessage({exit_code:envelope.exit_code,body:JSON.parse(envelope.body)});}
 catch {self.postMessage({exit_code:4,body:{category:'internal',message:'Analysis failed; no equivalence conclusion.'}});}
};
