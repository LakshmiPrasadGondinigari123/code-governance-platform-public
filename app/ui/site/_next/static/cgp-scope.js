/* Keeps the chosen repository in step between the original app pages and the custom pages.
   The address bar (?repo=) is the truth on the original pages; it is mirrored to storage so the custom pages follow. */
(function(){
  var KEY='cgp_repo';
  function cur(){ var m=location.search.match(/[?&]repo=([^&]+)/); return m?decodeURIComponent(m[1]):''; }
  function put(v){ try{ if(v) localStorage.setItem(KEY,v); else localStorage.removeItem(KEY); }catch(e){} }
  function stored(){ try{ return localStorage.getItem(KEY)||''; }catch(e){ return ''; } }
  if(location.pathname==='/login') return;
  var last=cur();
  put(last);                       // whatever this page shows is now the choice
  setInterval(function(){ var c=cur(); if(c!==last){ last=c; put(c); } },400);
  // menu links carry the choice to the next page
  document.addEventListener('click',function(ev){
    var a=ev.target&&ev.target.closest?ev.target.closest('nav a[href], aside a[href]'):null; if(!a) return;
    var href=a.getAttribute('href')||''; if(!href||href[0]!=='/'||href.indexOf('//')===0||href.indexOf('/_next/')===0) return;
    if(ev.metaKey||ev.ctrlKey||ev.shiftKey||a.target==='_blank') return;
    var s=cur()||stored(); if(!s||/[?&]repo=/.test(href)) return;
    ev.preventDefault(); ev.stopPropagation();
    location.href=href.split('#')[0]+(href.indexOf('?')>=0?'&':'?')+'repo='+encodeURIComponent(s);
  },true);
})();