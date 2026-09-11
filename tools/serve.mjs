import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
const files=new Map([
 ['/web/', ['web/index.html','text/html; charset=utf-8']],
 ...['app.js','worker.js','style.css'].map(n=>['/web/'+n,['web/'+n,n.endsWith('.css')?'text/css':'text/javascript']]),
 ['/_build/js/debug/build/browser/browser.js',['_build/js/debug/build/browser/browser.js','text/javascript']]
]);
const server=createServer(async(req,res)=>{
 if(req.url==='/favicon.ico'){res.writeHead(204);res.end();return;}
 const item=files.get(new URL(req.url,'http://127.0.0.1').pathname);
 if(req.method!=='GET'||!item){res.writeHead(404);res.end('Not found');return;}
 try {const body=await readFile(new URL('../'+item[0],import.meta.url));res.writeHead(200,{'content-type':item[1],'cache-control':'no-store','x-content-type-options':'nosniff'});res.end(body);}
 catch {res.writeHead(503);res.end('Build first: moon build --target js');}
});
server.listen(8765,'127.0.0.1',()=>console.log('MoonPolicyProof: http://127.0.0.1:8765/web/ (loopback only; Ctrl+C to stop)'));
