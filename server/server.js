// 专转本 ZHIYAN · 账号与同步服务（零依赖，node server.js 即可）
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=+process.env.PORT||8899;
const DB=path.join(__dirname,'data.json');
const ADMIN_KEY=process.env.ADMIN_KEY||'zhiyan-admin';
function load(){ try{ return JSON.parse(fs.readFileSync(DB,'utf8')); }catch(e){ return {users:{}}; } }
function save(db){ fs.writeFileSync(DB,JSON.stringify(db,null,1)); }
function hash(pass,salt){ return crypto.createHash('sha256').update(salt+':'+pass).digest('hex'); }
function newToken(){ return crypto.randomBytes(24).toString('hex'); }
function body(req){ return new Promise(r=>{ let b=''; req.on('data',c=>{ b+=c; if(b.length>8e6) req.destroy(); }); req.on('end',()=>{ try{ r(JSON.parse(b||'{}')); }catch(e){ r({}); } }); }); }
function json(res,code,obj){ const s=JSON.stringify(obj); res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*','Cache-Control':'no-store'}); res.end(s); }
let adminFail=0, adminLockUntil=0;
function lockLeft(){ const t=Math.ceil((adminLockUntil-Date.now())/1000); if(t<=0){ if(adminLockUntil){ adminLockUntil=0; adminFail=0; } return 0; } return t; }
function adminSig(){ return crypto.createHmac('sha256',(process.env.ADMIN_PASS||'zhiyan-admin')).update('zhiyan-admin-v1').digest('hex'); }
function adminOK(req){ const c=req.headers.cookie||''; const m=c.match(/zd=([a-f0-9]+)/); return !!m && m[1]===adminSig(); }
function esc(s){ return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
const ADMIN_LOGIN=`<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui;background:#0e1116;color:#e8edf4;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.b{width:280px}input,button{width:100%;height:42px;margin-top:10px;border-radius:10px;border:1px solid #263140;background:#151c25;color:#e8edf4;font-size:14px;padding:0 12px}
button{background:#35d39a;color:#08110d;border:0;font-weight:600}.e{color:#ff7a7a;font-size:12px;margin-top:8px}</style>
<div class=b><h3 style="font-size:15px;margin:0 0 4px">后台登录</h3><div style="color:#8b94a6;font-size:12px">仅作者可用</div>
<form method=post action=/admin/login><input type=password name=pass placeholder=管理密码 autofocus><button>进入</button></form>
<div class=e>%ERR%</div></div>`;
function findUser(db,token){ for(const k in db.users){ if(db.users[k].token===token) return k; } return null; }

http.createServer(async (req,res)=>{
  const u=new URL(req.url,'http://x');
  if(req.method==='OPTIONS'){ res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*','Access-Control-Allow-Methods':'*'}); return res.end(); }
  if(u.pathname==='/api/register' && req.method==='POST'){
    const {id,pass}=await body(req);
    const name=String(id||'').trim(), pw=String(pass||'');
    if(name.length<2||name.length>20) return json(res,400,{error:'ID 需 2–20 个字'});
    if(pw.length<4) return json(res,400,{error:'密码至少 4 位'});
    const db=load();
    if(db.users[name]) return json(res,409,{error:'这个 ID 已被注册'});
    const salt=crypto.randomBytes(8).toString('hex');
    db.users[name]={salt,hash:hash(pw,salt),token:newToken(),created:Date.now(),lastSync:0,data:null};
    save(db);
    return json(res,200,{ok:true,id:name,token:db.users[name].token});
  }
  if(u.pathname==='/api/login' && req.method==='POST'){
    const {id,pass}=await body(req);
    const name=String(id||'').trim();
    const db=load(), usr=db.users[name];
    if(!usr) return json(res,404,{error:'没有这个 ID，先注册'});
    if(usr.hash!==hash(String(pass||''),usr.salt)) return json(res,403,{error:'密码不对'});
    usr.token=newToken(); usr.lastSync=Date.now(); save(db);
    return json(res,200,{ok:true,id:name,token:usr.token,hasData:!!usr.data});
  }
  if(u.pathname==='/api/sync' && req.method==='POST'){
    const {token,data}=await body(req);
    const db=load(); const name=findUser(db,token);
    if(!name) return json(res,401,{error:'登录已失效，重新登录'});
    db.users[name].data=data; db.users[name].lastSync=Date.now(); save(db);
    return json(res,200,{ok:true,at:db.users[name].lastSync});
  }
  if(u.pathname==='/api/load'){
    const token=u.searchParams.get('token')||'';
    const db=load(); const name=findUser(db,token);
    if(!name) return json(res,401,{error:'登录已失效'});
    db.users[name].lastSync=Date.now(); save(db);
    return json(res,200,{ok:true,id:name,data:db.users[name].data});
  }
  // ---------- 后台（仅作者）----------
  const ADMIN_PASS=process.env.ADMIN_PASS||'zhiyan-admin';
  if(u.pathname==='/admin' && req.method==='GET'){
    if(!adminOK(req)){ res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'}); return res.end(ADMIN_LOGIN.replace('%ERR%',lockLeft()?('尝试过多，请 '+lockLeft()+' 秒后再试'):'')); }
    const db=load(); const rows=Object.keys(db.users).map(k=>{
      const x=db.users[k];
      return `<tr><td><b>${esc(k)}</b></td><td>${new Date(x.created).toLocaleString('zh-CN')}</td><td>${x.lastSync?new Date(x.lastSync).toLocaleString('zh-CN'):'—'}</td><td>${x.data?Math.round(JSON.stringify(x.data).length/1024)+' KB':'未同步'}</td></tr>`;
    }).join('');
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});
    return res.end(`<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui;margin:16px;background:#0e1116;color:#e8edf4}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #263140;padding:8px;text-align:left}h2{font-size:16px}.k{color:#8b94a6;font-size:12px}a{color:#35d39a}</style>
<h2>专转本 ZHIYAN · 后台</h2>
<div class=k>注册用户 <b>${Object.keys(db.users).length}</b> 个　<a href="/admin/logout">退出</a></div>
<table><tr><th>ID</th><th>注册时间</th><th>最近同步</th><th>数据量</th></tr>${rows||'<tr><td colspan=4 class=k>还没有人注册</td></tr>'}</table>`);
  }
  if(u.pathname==='/admin/login' && req.method==='POST'){
    if(lockLeft()) return json(res,429,{error:'尝试过多，稍后再试'});
    const {pass}=await body(req);
    if(String(pass||'')!==ADMIN_PASS){ adminFail++; if(adminFail>=5){ adminLockUntil=Date.now()+600000; } return json(res,403,{error:'密码不对'}); }
    adminFail=0;
    const sig=adminSig();
    res.writeHead(200,{'Content-Type':'application/json','Set-Cookie':'zd='+sig+'; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400','Access-Control-Allow-Origin':'*'});
    return res.end(JSON.stringify({ok:true}));
  }
  if(u.pathname==='/admin/logout'){
    res.writeHead(302,{'Set-Cookie':'zd=; Path=/; Max-Age=0','Location':'/admin'}); return res.end();
  }
  if(u.pathname==='/') { res.writeHead(200,{'Content-Type':'text/plain; charset=utf-8'}); return res.end('ZHIYAN sync server ok'); }
  json(res,404,{error:'not found'});
}).listen(PORT,'0.0.0.0',()=>console.log('sync server on :'+PORT));
