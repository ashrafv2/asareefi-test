/* مصاريفي 2.0 — عامل خدمة للإصدار الرسمي، دون تخزين بيانات مالية. */
'use strict';
const CACHE='masareefi-official-v2-shell-20261029';
const PREFIX='masareefi-official-v2-shell-';
const FILES=['./','./index.html','./manifest.webmanifest','./icon-192.png','./icon-512.png'];
self.addEventListener('install', event=>{
 event.waitUntil(
   caches.open(CACHE)
   .then(cache=>cache.addAll(FILES))
   .then(()=>self.skipWaiting())
 );
});
self.addEventListener('activate',event=>{
 event.waitUntil(
  caches.keys()
   .then(keys=>Promise.all(keys.filter(key=>(key.startsWith(PREFIX)&&key!==CACHE)||key.startsWith('masareefi-shell-')).map(key=>caches.delete(key))))
   .then(()=>self.clients.claim())
 );
});
self.addEventListener('fetch',event=>{
 const request=event.request;
 if(request.method!=='GET')return;
 const url=new URL(request.url);
 const scope=new URL(self.registration.scope);
 if(url.origin!==scope.origin||!url.pathname.startsWith(scope.pathname))return;
 const relative=url.pathname.slice(scope.pathname.length);
 const allowed=['','index.html','manifest.webmanifest','icon-192.png','icon-512.png'];
 if(request.mode!=='navigate'&&!allowed.includes(relative))return;
 event.respondWith(
  fetch(request).then(async response=>{
   if(response.ok){
    const cache=await caches.open(CACHE);
    try{await cache.put(request,response.clone())}catch(error){}
   }
   return response;
  }).catch(async()=>{
   const cache=await caches.open(CACHE);
   return await cache.match(request,{ignoreSearch:true})||
     await cache.match('./index.html')||
     Response.error();
  })
 );
});
