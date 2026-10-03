
const T="__TOKEN__";let F=[],sel=null,edited=null,view="body",lastId=0,checked=new Set(),paused=false,followNew=true,noiseList=["google.com","doubleclick.net","analytics.google.com","googletagmanager.com","googleadservices.com","clients6.google.com","gstatic.com","update.googleapis.com","mtalk.google.com"];
const $=i=>document.getElementById(i);
async function api(p,o={}){const r=await fetch(p,{...o,headers:{"X-Sniffle-Token":T}});return r.json()}
const pretty=s=>{try{return JSON.stringify(JSON.parse(s),null,2)}catch(e){return s}};
const syntaxHighlight=json=>{
  if(typeof json!=='string')json=JSON.stringify(json);
  json=json.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,function(match){
    let cls='json-number';
    if(/^"/.test(match)){
      if(/:$/.test(match))cls='json-key';
      else cls='json-string';
    }else if(/true|false/.test(match))cls='json-bool';
    else if(/null/.test(match))cls='json-null';
    return '<span class="'+cls+'">'+match+'</span>';
  });
};
const hdrsText=a=>a.map(x=>x[0]+": "+x[1]).join("\n");
const parseHdrs=t=>t.split("\n").map(l=>{const i=l.indexOf(":");return i>0?[l.slice(0,i).trim(),l.slice(i+1).trim()]:null}).filter(Boolean);
const toObj=a=>Object.fromEntries(a);
function toast(msg){const t=document.createElement("div");t.className="toast";t.textContent=msg;document.body.appendChild(t);setTimeout(()=>t.remove(),2000)}
function formatSize(s){if(s<1024)return s+" B";if(s<1024*1024)return (s/1024).toFixed(1)+" KB";return (s/1024/1024).toFixed(1)+" MB"}
function formatTime(s){if(!s)return"-";const d=new Date(s);if(isNaN(d.getTime()))return"-";return d.toTimeString().slice(0,8)}
function methodBadge(m){const cls="method-"+m.toLowerCase();return `<span class="method-badge ${cls}">${m}</span>`}
function isNoise(f){return noiseList.some(n=>f.host.includes(n))}
function matchesFilter(f,q){
  if(!q)return true;
  q=q.toLowerCase();
  if(q.startsWith("host:"))return f.host.toLowerCase().includes(q.slice(5));
  if(q.startsWith("status:")){const s=q.slice(7);if(s=="2xx")return f.status>=200&&f.status<300;if(s=="4xx")return f.status>=400&&f.status<500;if(s=="5xx")return f.status>=500;return f.status==parseInt(s)}
  if(q.startsWith("method:"))return f.method.toLowerCase()==q.slice(7);
  return (f.method+" "+f.url+" "+f.status+" "+f.req.body+" "+(f.res?f.res.body:"")).toLowerCase().includes(q);
}

function draw(){
  const q=$("q").value.toLowerCase(),tb=$("rows");tb.textContent="";
  const hideNoise=$("hide-noise").classList.contains("active");
  F.filter(f=>!hideNoise||!isNoise(f)).filter(f=>matchesFilter(f,q)).slice(-500).forEach(f=>{
    const tr=document.createElement("tr");tr.className="r"+(f===sel?" on":"");
    if(f.id===lastId)tr.classList.add("new-row");
    const cb=document.createElement("input");
    cb.type="checkbox";cb.checked=checked.has(f.id);
    cb.onclick=e=>{e.stopPropagation();if(cb.checked)checked.add(f.id);else checked.delete(f.id)};
    const td=document.createElement("td");td.appendChild(cb);tr.appendChild(td);
    
    const idTd=document.createElement("td");idTd.textContent=f.id;tr.appendChild(idTd);
    
    const mTd=document.createElement("td");mTd.innerHTML=methodBadge(f.method);tr.appendChild(mTd);
    
    const urlTd=document.createElement("td");urlTd.className="host-path";
    urlTd.innerHTML=`<span class="host">${f.host}</span><span class="path">${f.path}</span>`;tr.appendChild(urlTd);
    
    const sTd=document.createElement("td");sTd.textContent=f.status||"ERR";sTd.className="s"+String(f.status)[0];tr.appendChild(sTd);
    
    const szTd=document.createElement("td");szTd.textContent=formatSize(f.size);tr.appendChild(szTd);
    
    const tTd=document.createElement("td");tTd.textContent=formatTime(f.iso);if(f.ms>1000)tTd.classList.add("slow");tr.appendChild(tTd);
    
    tr.onclick=()=>pick(f);tb.appendChild(tr)});
}
function pick(f){
  sel=f;edited=null;$("none").hidden=true;$("ed").hidden=false;$("rs").hidden=false;
  $("m").value=f.method;$("u").value=f.url;$("h").value=hdrsText(f.req.headers);$("b").value=f.req.body;
  show("body");draw();
}
function show(v){
  view=v;$("t1").classList.toggle("on",v=="body");$("t2").classList.toggle("on",v=="headers");$("t3").classList.toggle("on",v=="raw");
  const r=sel&&sel.res&&{status:sel.status,headers:sel.res.headers,body:sel.res.body,ms:sel.ms};
  if(!r||!sel.res){$("rst").textContent=r&&r.error?r.error:"";$("rh").value="";$("rb").innerHTML="";$("rraw").value="";return}
  $("rst").textContent=r.status+" · "+r.ms+" ms"+(r.ms>1000?" (slow)":"");
  $("rh").value=hdrsText(r.headers);
  $("rraw").value=r.body;
  $("rb").style.display=v=="body"?"block":"none";
  $("rh").style.display=v=="headers"?"block":"none";
  $("rh").style.height=v=="headers"?"auto":"60px";
  $("rraw").style.display=v=="raw"?"block":"none";
  $("rraw").style.height=v=="raw"?"auto":"60px";
  try{const parsed=JSON.parse(r.body);$("rb").innerHTML=syntaxHighlight(parsed)}catch(e){$("rb").textContent=pretty(r.body)}
}
const reqObj=()=>({method:$("m").value.trim()||"GET",url:$("u").value.trim(),headers:parseHdrs($("h").value),body:$("b").value});
const curId=s=>"'"+s.replace(/'/g,"'\\''")+"'";
$("send").onclick=async()=>{
  $("rst").textContent="Sending…";
  edited=await api("/api/send",{method:"POST",body:JSON.stringify(reqObj())});show("body")};
$("reset").onclick=()=>sel&&pick(sel);
$("t1").onclick=()=>show("body");$("t2").onclick=()=>show("headers");$("t3").onclick=()=>show("raw");
$("cj").onclick=e=>{const r=reqObj();toast("JSON copied");navigator.clipboard.writeText(JSON.stringify({method:r.method,url:r.url,headers:toObj(r.headers),body:pretty(r.body)==r.body?r.body:JSON.parse(r.body)},null,2))};
$("cc").onclick=e=>{const r=reqObj();let c="curl -X "+r.method+" "+curId(r.url);
  r.headers.forEach(h=>{if(!/^(host|content-length)$/i.test(h[0]))c+=" -H "+curId(h[0]+": "+h[1])});
  if(r.body)c+=" --data-raw "+curId(r.body);toast("cURL copied");navigator.clipboard.writeText(c)};
$("cf").onclick=e=>{const r=reqObj();toast("fetch copied");navigator.clipboard.writeText(`await fetch("${r.url}",{method:"${r.method}",headers:${JSON.stringify(toObj(r.headers))},body:${JSON.stringify(r.body)}})`)};
$("cp").onclick=e=>{const r=reqObj();toast("Python copied");navigator.clipboard.writeText(`import requests\nrequests.${r.method.toLowerCase()}("${r.url}",headers=${JSON.stringify(toObj(r.headers))},json=${JSON.stringify(r.body)})`)};
$("cb").onclick=e=>{toast("Body copied");navigator.clipboard.writeText($("rb").textContent)};
$("cr").onclick=e=>{const r=sel&&sel.res;if(!r)return;let b=r.body;try{b=JSON.parse(b)}catch(x){}toast("JSON copied");navigator.clipboard.writeText(JSON.stringify({status:r.status,headers:toObj(r.headers),body:b},null,2))};
$("delete-all").onclick=async()=>{
  if(confirm("Delete all flows?")){await api("/api/clear",{method:"POST"});F=[];sel=null;checked.clear();
  $("ed").hidden=$("rs").hidden=true;$("none").hidden=false;draw();}};
$("delete-checked").onclick=async()=>{
  if(checked.size===0){alert("No rows checked");return}
  if(confirm("Delete "+checked.size+" checked flow(s)?")){await api("/api/delete",{method:"POST",body:JSON.stringify({ids:[...checked]})});
  F=F.filter(f=>!checked.has(f.id));if(sel&&checked.has(sel.id)){sel=null;$("ed").hidden=$("rs").hidden=true;$("none").hidden=false}
  checked.clear();draw();}};
$("check-all").onclick=e=>{
  const q=$("q").value.toLowerCase();
  const hideNoise=$("hide-noise").classList.contains("active");
  const shown=F.filter(f=>!hideNoise||!isNoise(f)).filter(f=>matchesFilter(f,q));
  const checkedNow=e.target.checked;
  shown.forEach(f=>{if(checkedNow)checked.add(f.id);else checked.delete(f.id)});
  draw();
};
$("pause").onclick=()=>{paused=!paused;$("pause").textContent=paused?"▶":"⏸";toast(paused?"Paused":"Resumed")};
$("follow").onclick=()=>{followNew=!followNew;$("follow").classList.toggle("active",followNew);toast(followNew?"Following newest":"Stopped following")};
$("hide-noise").onclick=()=>{$("hide-noise").classList.toggle("active");draw()};
document.querySelectorAll(".quick-filter button").forEach(b=>b.onclick=()=>{$("q").value=b.dataset.filter;draw()});
document.addEventListener("keydown",e=>{
  if(e.target.tagName==="INPUT"||e.target.tagName==="TEXTAREA")return;
  if(e.key==="ArrowDown"){const idx=F.indexOf(sel);if(idx<F.length-1)pick(F[idx+1])}
  else if(e.key==="ArrowUp"){const idx=F.indexOf(sel);if(idx>0)pick(F[idx-1])}
  else if(e.key==="/"){$("q").focus();e.preventDefault()}
  else if(e.key==="Delete"&&sel){if(confirm("Delete this flow?")){api("/api/delete",{method:"POST",body:JSON.stringify({ids:[sel.id]})});F=F.filter(f=>f.id!==sel.id);sel=null;$("ed").hidden=$("rs").hidden=true;$("none").hidden=false;draw()}
}});

// Draggable divider
const divider=$("divider");
const leftPanel=$("left");
const rightPanel=$("right");
const mainEl=$("main");
let isResizing=false;

divider.addEventListener("mousedown",e=>{isResizing=true;document.body.style.cursor="col-resize";e.preventDefault()});
document.addEventListener("mousemove",e=>{if(!isResizing)return;const rect=mainEl.getBoundingClientRect();const newLeftWidth=((e.clientX-rect.left)/rect.width)*100;if(newLeftWidth>20&&newLeftWidth<80){leftPanel.style.flex=`0 0 ${newLeftWidth}%`;rightPanel.style.flex="1 1 auto"}});
document.addEventListener("mouseup",()=>{if(isResizing){isResizing=false;document.body.style.cursor="default"}});
$("export").onclick=async()=>{
  const format=$("export-format").value;
  const res=await fetch("/api/export",{method:"POST",headers:{"X-Sniffle-Token":T},
    body:JSON.stringify({scope:$("export-scope").value,format,filter:$("q").value,checked_ids:[...checked]})});
  if(!res.ok){let m="Export failed";try{m=(await res.json()).error||m}catch(e){}alert(m);return}
  const name=(res.headers.get("Content-Disposition")||"").match(/filename="([^"]+)"/);
  const url=URL.createObjectURL(await res.blob());
  const a=document.createElement("a");a.href=url;a.download=name?name[1]:"sniffle."+format;
  document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)};
$("q").oninput=draw;
async function poll(){
  if(paused)return;
  try{const n=await api("/api/flows?since="+lastId);if(n.length){F.push(...n);n.forEach(f=>lastId=f.id);draw();if(followNew){const tb=$("rows");tb.scrollTop=tb.scrollHeight}}
    $("st").textContent="● capturing · "+F.length+" requests"}
  catch(e){$("st").textContent="○ disconnected"}}
setInterval(poll,1000);poll();
