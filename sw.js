const CACHE='masareefi-2-20261028-approved-v1';
self.addEventListener('install',event=>{event.waitUntil(self.skipWaiting())});
self.addEventListener('activate',event=>{event.waitUntil(self.clients.claim())});
self.addEventListener('fetch',event=>{ /* no interception during review: always fetch the newest version */ });
