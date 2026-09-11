const $=id=>document.getElementById(id);
let worker=null,timer=null;
function finish(){if(worker)worker.terminate();worker=null;clearTimeout(timer);$('compare').disabled=false;$('cancel').disabled=true;for(const id of ['before','after','scope','example'])$(id).disabled=false;}
function example(){
 $('before').value='moonpolicyproof 1\ndefault deny\nrule web allow tcp 10.0.0.0/24 192.0.2.10/32 * 443\n';
 $('after').value=$('before').value.replace('10.0.0.0/24','10.0.0.0/16');$('scope').value='';
}
function stale(){$('status').textContent='输入已更新，等待重新分析';$('output').textContent='尚未对当前输入得出结论。';}
$('example').onclick=()=>{example();stale();};
for(const id of ['before','after','scope'])$(id).oninput=stale;
$('cancel').onclick=()=>{finish();$('status').textContent='已取消：没有得出结论';$('output').textContent='取消不代表策略等价。';};
$('compare').onclick=()=>{
 finish();$('compare').disabled=true;$('cancel').disabled=false;for(const id of ['before','after','scope','example'])$(id).disabled=true;$('status').textContent='分析中…';$('output').textContent='正在编译完整流量域并验证反例。';
 worker=new Worker('./worker.js',{type:'module'});
 worker.onmessage=({data})=>{finish();$('status').textContent=data.exit_code===0?'在报告范围内等价':data.exit_code===1?'发现语义变化':'分析失败：没有得出结论';$('output').textContent=JSON.stringify(data.body,null,2);};
 worker.onerror=()=>{finish();$('status').textContent='执行失败：没有得出结论';$('output').textContent='请先构建 JS 产物，使用本地 HTTP 服务打开页面。';};
 timer=setTimeout(()=>{finish();$('status').textContent='分析超时：没有得出结论';$('output').textContent='30 秒终止 Worker；可缩小规则集或使用有界 CLI。';},30000);
 const req={command:'diff',before:$('before').value,after:$('after').value};if($('scope').value.trim())req.scope=$('scope').value.trim();worker.postMessage(req);
};
example();
