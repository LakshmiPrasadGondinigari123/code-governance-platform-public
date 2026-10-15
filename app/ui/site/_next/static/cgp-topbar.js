/* Common top bar for the custom pages: title, global search, live status, theme toggle, signed-in user. */
(function(){
  var TOKEN=null; try{TOKEN=localStorage.getItem('cgp_token')}catch(e){}
  function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
  function isDark(){ var t=null; try{t=localStorage.getItem('theme')}catch(e){} if(t==='dark') return true; if(t==='light') return false; return !!(window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').matches); }
  function applyTheme(){ var d=isDark(), h=document.documentElement; h.classList.toggle('dark',d); h.classList.toggle('light',!d); var b=document.getElementById('cgpTheme'); if(b) b.innerHTML=d?'&#9728;':'&#9790;'; }
  function api(p){ return fetch(p,{headers:{Authorization:'Bearer '+TOKEN}}).then(function(r){ if(!r.ok) throw new Error(p); return r.json(); }); }

  var css='\
.cgp-top{height:60px;display:flex;align-items:center;gap:14px;padding:0 24px;background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:20}\
.cgp-title{font-weight:700;font-size:14px;white-space:nowrap}\
.cgp-repo{max-width:260px;background:rgba(148,163,184,.12);border:1px solid var(--line);color:var(--text);border-radius:12px;padding:9px 12px;font:inherit;font-size:13.5px;font-weight:600}\.cgp-search{position:relative;flex:1;max-width:560px;margin:0 auto 0 14px}\
.cgp-search input{width:100%;background:rgba(148,163,184,.12);border:1px solid var(--line);color:var(--text);border-radius:12px;padding:10px 54px 10px 38px;font:inherit;font-size:13.5px;outline:none}\
.cgp-search input:focus{border-color:var(--accent)}\
.cgp-search .ic{position:absolute;left:13px;top:50%;transform:translateY(-50%);opacity:.6;font-size:14px}\
.cgp-search kbd{position:absolute;right:10px;top:50%;transform:translateY(-50%);font:11px ui-monospace,Consolas,monospace;border:1px solid var(--line);border-radius:6px;padding:1px 6px;color:var(--muted)}\
.cgp-res{position:absolute;top:46px;left:0;right:0;background:var(--card,#fff);color:var(--text);border:1px solid var(--line);border-radius:12px;box-shadow:0 12px 32px rgba(0,0,0,.25);max-height:420px;overflow:auto;display:none;z-index:30}\
.cgp-res h6{margin:0;padding:10px 14px 4px;font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}\
.cgp-res a{display:block;padding:8px 14px;font-size:13.5px;color:var(--text)}.cgp-res a:hover,.cgp-res a.hi{background:rgba(99,102,241,.14)}\
.cgp-res a small{display:block;color:var(--muted);font-size:12px}\
.cgp-live{font-size:11px;font-weight:800;border:1px solid #14532d;color:#4ade80;border-radius:999px;padding:3px 10px;white-space:nowrap}\
.cgp-live.off{border-color:#7f1d1d;color:#f87171}\
.cgp-btn{width:34px;height:34px;border-radius:50%;border:0;background:transparent;color:var(--text);cursor:pointer;font-size:17px}.cgp-btn:hover{background:rgba(148,163,184,.18)}\
.cgp-user{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600}\
.cgp-av{width:30px;height:30px;border-radius:50%;background:#fed7aa;color:#c2410c;display:grid;place-items:center;font-size:12px;font-weight:800}\
@media(max-width:700px){.cgp-user span{display:none}.cgp-title{display:none}}';

  var KEY='cgp_repo';
  function getScope(){ var m=location.search.match(/[?&]repo=([^&]+)/); if(m) return decodeURIComponent(m[1]); try{ return localStorage.getItem(KEY)||''; }catch(e){ return ''; } }
  function fixLinks(){ var s=getScope(); document.querySelectorAll('.side .nav a').forEach(function(a){ var base=(a.getAttribute('href')||'').split('?')[0]; a.setAttribute('href', base+(s?('?repo='+encodeURIComponent(s)):'')); }); }
  window.cgpScope=getScope;
  window.cgpSetScope=function(id,silent){
    id=id||'';
    try{ if(id) localStorage.setItem(KEY,id); else localStorage.removeItem(KEY); }catch(e){}
    try{ var u=new URL(location.href); if(id) u.searchParams.set('repo',id); else u.searchParams.delete('repo'); history.replaceState(null,'',u.pathname+u.search+u.hash); }catch(e){}
    var s=document.getElementById('cgpRepo'); if(s && s.value!==id) s.value=id;
    fixLinks();
    if(!silent) window.dispatchEvent(new CustomEvent('cgp-repo',{detail:id}));
  };  var data=null, loading=null;
  function load(){
    if(data) return Promise.resolve(data);
    if(loading) return loading;
    var out={repos:[],findings:[],controls:[]};
    function page(n){ return api('/findings?page_size=500&page='+n).then(function(d){ out.findings=out.findings.concat(d.items||[]); if(d.has_more&&n<10) return page(n+1); }); }
    loading=Promise.all([
      api('/repositories').then(function(d){ out.repos=d.items||d.repositories||[]; }).catch(function(){}),
      page(1).catch(function(){}),
      api('/governance/controls').then(function(d){ out.controls=d.controls||[]; }).catch(function(){})
    ]).then(function(){ data=out; return out; });
    return loading;
  }
  function search(q){
    q=q.trim().toLowerCase(); if(!q) return null;
    var has=function(s){return String(s||'').toLowerCase().indexOf(q)>=0};
    var repos=data.repos.filter(function(r){return has(r.name)||has(r.repo_ref)}).slice(0,5);
    var seen={}, fnd=data.findings.filter(function(f){ return has(f.title)||has(f.path||f.file)||has(f.repository_name)||has(f.data_type); }).slice(0,40);
    var grouped=[]; fnd.forEach(function(f){ var k=f.title+'|'+(f.path||f.file); if(!seen[k]){ seen[k]=1; grouped.push(f); } }); grouped=grouped.slice(0,6);
    var ctr=data.controls.filter(function(c){return has(c.name)||has(c.control_id)}).slice(0,4);
    return {repos:repos,findings:grouped,controls:ctr};
  }
  function render(res,box){
    if(!res||(!res.repos.length&&!res.findings.length&&!res.controls.length)){ box.innerHTML='<h6>No matches</h6><a style="color:var(--muted)">Try a repository, file, data type or control name.</a>'; return; }
    var h='';
    if(res.repos.length) h+='<h6>Repositories</h6>'+res.repos.map(function(r){return '<a href="/ai-inventory?repo='+encodeURIComponent(r.repository_id||r.id)+'">'+esc(r.name)+'<small>Open its AI card</small></a>'}).join('');
    if(res.findings.length) h+='<h6>Findings</h6>'+res.findings.map(function(f){return '<a href="/findings/'+encodeURIComponent(f.id)+'">'+esc(f.title)+'<small>'+esc(f.path||f.file||'')+' · '+esc(f.repository_name||'')+'</small></a>'}).join('');
    if(res.controls.length) h+='<h6>Governance controls</h6>'+res.controls.map(function(c){return '<a href="/controls">'+esc(c.name)+'<small>Open Governance Controls</small></a>'}).join('');
    box.innerHTML=h;
  }
  function build(){
    var top=document.querySelector('.top'); if(!top||document.getElementById('cgpSearch')) return;
    var st=document.createElement('style'); st.textContent=css; document.head.appendChild(st);
    var tEl=top.querySelector('b'); var title=tEl?tEl.textContent:(document.title||''); var titleId=(tEl&&tEl.id)||'';
    top.className='top cgp-top'; top.removeAttribute('style');
    top.innerHTML='<span class="cgp-title"'+(titleId?' id="'+titleId+'"':'')+'>'+esc(title)+'</span>'+
      '<select id="cgpRepo" class="cgp-repo" title="Repository"><option value="">All repositories</option></select>'+
      '<div class="cgp-search"><span class="ic">&#128269;</span><input id="cgpSearch" type="search" autocomplete="off" placeholder="Search repositories, findings, evidence, controls…"><kbd>⌘K</kbd><div class="cgp-res" id="cgpRes"></div></div>'+
      '<span class="cgp-live" id="live">&#9679; LIVE</span>'+
      '<button class="cgp-btn" id="cgpTheme" type="button" title="Switch light / dark"></button>'+
      '<div class="cgp-user"><div class="cgp-av" id="cgpAv">A</div><span id="cgpUser">admin</span></div>';
    applyTheme();
    document.getElementById('cgpTheme').onclick=function(){ var n=isDark()?'light':'dark'; try{localStorage.setItem('theme',n)}catch(e){} applyTheme(); };
    var inp=document.getElementById('cgpSearch'), box=document.getElementById('cgpRes'), timer=null;
    inp.addEventListener('focus',function(){ load(); });
    inp.addEventListener('input',function(){ clearTimeout(timer); timer=setTimeout(function(){ load().then(function(){ var r=search(inp.value); if(!r){ box.style.display='none'; return; } render(r,box); box.style.display='block'; }); },160); });
    document.addEventListener('click',function(e){ if(!e.target.closest||!e.target.closest('.cgp-search')) box.style.display='none'; });
    document.addEventListener('keydown',function(e){ if((e.metaKey||e.ctrlKey)&&String(e.key).toLowerCase()==='k'){ e.preventDefault(); inp.focus(); inp.select(); } if(e.key==='Escape'){ box.style.display='none'; inp.blur(); } });
    if(TOKEN){
    function fillRepos(){
      api('/repositories').then(function(d){
        var items=d.items||d.repositories||[], sel=document.getElementById('cgpRepo'); if(!sel) return;
        var cur=getScope();
        var sig=items.map(function(r){return (r.repository_id||r.id)+':'+r.name}).join('|');
        if(sel.getAttribute('data-sig')!==sig){
          sel.innerHTML='<option value="">All repositories ('+items.length+')</option>'+items.map(function(r){return '<option value="'+esc(r.repository_id||r.id)+'">'+esc(r.name)+'</option>'}).join('');
          sel.setAttribute('data-sig',sig);
        }
        var exists=items.some(function(r){return (r.repository_id||r.id)===cur});
        if(cur && !exists){ window.cgpSetScope('',false); cur=''; }
        sel.value=cur; fixLinks();
      }).catch(function(){});
    }
    var rs=document.getElementById('cgpRepo');
    rs.onchange=function(){ window.cgpSetScope(rs.value||'',false); };
    fillRepos(); setInterval(fillRepos,45000);
    try{ var es=new EventSource('/findings/events?token='+encodeURIComponent(TOKEN)); es.onmessage=function(e){ try{ var d=JSON.parse(e.data); if(d&&d.type&&d.type!=='connected') setTimeout(fillRepos,600); }catch(_){} }; }catch(_){}
    window.addEventListener('storage',function(e){ if(e.key===KEY){ var s=document.getElementById('cgpRepo'); if(s){ s.value=e.newValue||''; } window.dispatchEvent(new CustomEvent('cgp-repo',{detail:e.newValue||''})); fixLinks(); } });
    var cur0=getScope(); if(cur0 && !/[?&]repo=/.test(location.search)){ window.cgpSetScope(cur0,true); }      fetch('/health').then(function(r){ if(!r.ok) throw 0; }).catch(function(){ var l=document.getElementById('live'); l.className='cgp-live off'; l.innerHTML='&#9675; OFFLINE'; });
      api('/auth/me').then(function(m){ var n=m.username||'admin'; document.getElementById('cgpUser').textContent=n; document.getElementById('cgpAv').textContent=n.slice(0,2).toUpperCase(); }).catch(function(){});
    }
  }
  window.addEventListener('storage',function(e){ if(!e.key||e.key==='theme') applyTheme(); });
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',build); else build();
})();
