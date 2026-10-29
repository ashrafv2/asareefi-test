/* Masareefi v21 test service worker.
 * Network-first app shell prevents stale app versions. Logo assets cache offline.
 * Never reads or caches bank messages, financial records, or personal merchant data.
 */
'use strict';
const SHELL_CACHE='masareefi-test-shell-v21-20261029';
const LOGO_CACHE='masareefi-test-logos-v19-20261029';
const OLD_PREFIXES=['masareefi-test-shell-','masareefi-test-logos-'];
const OFFICIAL_EJAR='https://www.ejar.sa/sites/default/files/EjarLogo_10.png';
const CORE=[
 './index.html','./cloud-sync.js','./manifest.webmanifest','./logos/catalog.json',
 './logos/stc.svg','./logos/amazon.svg','./logos/ejar-local.svg'
];
self.addEventListener('install',event=>{
 event.waitUntil((async()=>{
  const cache=await caches.open(SHELL_CACHE);
  // Logo files must exist for the offline library to install cleanly.
  await cache.addAll(CORE);
  await self.skipWaiting();
 })());
});
self.addEventListener('activate',event=>{
 event.waitUntil((async()=>{
  const names=await caches.keys();
  await Promise.all(names.filter(name=>
    OLD_PREFIXES.some(prefix=>name.startsWith(prefix))&&
    name!==SHELL_CACHE&&name!==LOGO_CACHE
  ).map(name=>caches.delete(name)));
  await self.clients.claim();
 })());
});
self.addEventListener('fetch',event=>{
 const req=event.request;
 if(req.method!=='GET')return;
 const url=new URL(req.url);
 const scope=new URL(self.registration.scope);
 if(url.href===OFFICIAL_EJAR){
  event.respondWith((async()=>{
   const store=await caches.open(LOGO_CACHE);
   const cached=await store.match(req);
   if(cached)return cached;
   try{
    const response=await fetch(req);
    if(response.ok||response.type==='opaque')store.put(req,response.clone()).catch(()=>{});
    return response;
   }catch(e){
    return await store.match(req)||Response.error();
   }
  })());
  return;
 }
 if(url.origin!==scope.origin||!url.pathname.startsWith(scope.pathname))return;
 const relative=url.pathname.slice(scope.pathname.length);
 if(req.mode==='navigate'||relative===''||relative==='index.html'){
  event.respondWith((async()=>{
    try{
      const response=await fetch(req);
      if(response.ok)(await caches.open(SHELL_CACHE)).put('./index.html',response.clone()).catch(()=>{});
      return response;
    }catch(e){
      const cache=await caches.open(SHELL_CACHE);
      return await cache.match('./index.html')||Response.error();
    }
  })());
  return;
 }
 if(relative==='logos/catalog.json'||relative==='manifest.webmanifest'||relative==='cloud-sync.js'){
  // Network first so a catalog update is visible without changing application code.
  event.respondWith((async()=>{
    const cache=await caches.open(SHELL_CACHE);
    try{
      const response=await fetch(req);
      if(response.ok)cache.put(req,response.clone()).catch(()=>{});
      return response;
    }catch(e){
      return await cache.match(req,{ignoreSearch:true})||Response.error();
    }
  })());
  return;
 }
 if(/^logos\/[a-z0-9-]+\.(svg|webp|png)$/.test(relative)||
    relative==='icon-192.png'||relative==='icon-512.png'){
  event.respondWith((async()=>{
    const cache=await caches.open(LOGO_CACHE);
    const cached=await cache.match(req,{ignoreSearch:true});
    if(cached)return cached;
    try{
      const response=await fetch(req);
      if(response.ok)cache.put(req,response.clone()).catch(()=>{});
      return response;
    }catch(e){return await cache.match(req,{ignoreSearch:true})||Response.error()}
  })());
 }
});
