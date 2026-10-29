/* Masareefi v22 device vault — optional trusted-device reconnect or passkey unlock.
 * Does not store Firebase password in any mode.
 * Trusted-device AES key is non-extractable but available to scripts on this origin.
 * A passkey PRF unlock, when supported, requires device authentication.
 * An opt-in is required before saving any cloud refresh token or encryption phrase.
 */
(function(){
'use strict';
const DB='masareefi_v22_device_vault', VERSION=1;
const STORE='records', KEY_STORE='keys', CURRENT='current';
const ENC=new TextEncoder(),DEC=new TextDecoder();
const toB64=bytes=>{
 let str='';for(let i=0;i<bytes.length;i+=32768)str+=String.fromCharCode(...bytes.subarray(i,i+32768));
 return btoa(str);
};
const fromB64=value=>{
 const bin=atob(value),bytes=new Uint8Array(bin.length);
 for(let i=0;i<bin.length;i++)bytes[i]=bin.charCodeAt(i);
 return bytes;
};
const random=n=>crypto.getRandomValues(new Uint8Array(n));
const available=()=>typeof indexedDB!=='undefined'&&!!crypto?.subtle;
function openDB(){
 if(!available())return Promise.reject(Error('التخزين الآمن غير متاح في هذا المتصفح.'));
 return new Promise((resolve,reject)=>{
  const request=indexedDB.open(DB,VERSION);
  request.onupgradeneeded=()=>{
   const db=request.result;
   if(!db.objectStoreNames.contains(STORE))db.createObjectStore(STORE);
   if(!db.objectStoreNames.contains(KEY_STORE))db.createObjectStore(KEY_STORE);
  };
  request.onsuccess=()=>resolve(request.result);
  request.onerror=()=>reject(request.error||Error('تعذر فتح تخزين الجهاز.'));
  request.onblocked=()=>reject(Error('أغلق نوافذ مصاريفي الأخرى وأعد المحاولة.'));
 });
}
async function getRecord(store,id){
 const db=await openDB();
 try{return await new Promise((resolve,reject)=>{
  const tx=db.transaction(store,'readonly'),req=tx.objectStore(store).get(id);
  req.onsuccess=()=>resolve(req.result||null);
  req.onerror=()=>reject(req.error||Error('تعذرت قراءة إعدادات الجهاز.'));
  tx.onabort=()=>reject(tx.error||Error('تعذرت قراءة إعدادات الجهاز.'));
 })}finally{db.close()}
}
async function putVault(record,key){
 const db=await openDB();
 try{return await new Promise((resolve,reject)=>{
  const tx=db.transaction([STORE,KEY_STORE],'readwrite');
  tx.objectStore(STORE).put(record,CURRENT);
  if(key)tx.objectStore(KEY_STORE).put(key,'automatic');
  else tx.objectStore(KEY_STORE).delete('automatic');
  tx.oncomplete=()=>resolve();
  tx.onabort=()=>reject(tx.error||Error('لم يُحفظ الاتصال المشفّر.'));
  tx.onerror=()=>reject(tx.error||Error('لم يُحفظ الاتصال المشفّر.'));
 })}finally{db.close()}
}
async function clear(){
 const db=await openDB();
 try{return await new Promise((resolve,reject)=>{
  const tx=db.transaction([STORE,KEY_STORE],'readwrite');
  tx.objectStore(STORE).delete(CURRENT);
  tx.objectStore(KEY_STORE).delete('automatic');
  tx.oncomplete=()=>resolve();
  tx.onabort=()=>reject(tx.error||Error('تعذر إزالة الاتصال المحفوظ.'));
 })}finally{db.close()}
}
async function metadata(){
 const row=await getRecord(STORE,CURRENT);
 if(!row||row.version!==1||!['automatic','passkey'].includes(row.mode))return null;
 return {mode:row.mode,projectId:row.projectId,email:row.email,uid:row.uid,createdAt:row.createdAt};
}
function verifySecrets(value){
 if(!value||typeof value!=='object'||typeof value.projectId!=='string'||
    typeof value.email!=='string'||typeof value.uid!=='string'||
    typeof value.refreshToken!=='string'||value.refreshToken.length<20||
    typeof value.phrase!=='string'||value.phrase.length<12)
  throw Error('بيانات الاتصال غير مكتملة؛ سجّل الدخول الكامل.');
 return {projectId:value.projectId,email:value.email,uid:value.uid,
  refreshToken:value.refreshToken,phrase:value.phrase};
}
function aad(row){
 return ENC.encode('masareefi-v22|'+row.mode+'|'+row.projectId+'|'+row.email+'|'+row.uid);
}
async function seal(row,secrets,key){
 const iv=random(12),bytes=ENC.encode(JSON.stringify(verifySecrets(secrets)));
 const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(row)},key,bytes);
 return {...row,iv:toB64(iv),cipher:toB64(new Uint8Array(cipher))};
}
async function unseal(row,key){
 if(typeof row.iv!=='string'||typeof row.cipher!=='string'||row.cipher.length>20000)
  throw Error('اتصال الجهاز المحفوظ غير صالح.');
 const plain=await crypto.subtle.decrypt({
  name:'AES-GCM',iv:fromB64(row.iv),additionalData:aad(row)
 },key,fromB64(row.cipher));
 const obj=verifySecrets(JSON.parse(DEC.decode(plain)));
 if(obj.projectId!==row.projectId||obj.email!==row.email||obj.uid!==row.uid)
  throw Error('بيانات الاتصال المحفوظة لا تطابق هذا الحساب.');
 return obj;
}
function rowFor(secrets,mode){
 return {version:1,mode,projectId:secrets.projectId,email:secrets.email,uid:secrets.uid,
  createdAt:new Date().toISOString()};
}
async function rememberAutomatic(secrets){
 const verified=verifySecrets(secrets);
 if(!available())throw Error('المتصفح لا يدعم حفظ اتصال مشفر.');
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 const record=await seal(rowFor(verified,'automatic'),verified,key);
 await putVault(record,key);
 return true;
}
async function restoreAutomatic(){
 const record=await getRecord(STORE,CURRENT);
 if(!record||record.mode!=='automatic')return null;
 const key=await getRecord(KEY_STORE,'automatic');
 if(!key)throw Error('فُقد مفتاح حماية الاتصال على هذا الجهاز. سجّل الدخول الكامل لإعادة تفعيله.');
 try{return await unseal(record,key)}
 catch(e){throw Error('تعذر فتح الاتصال المحفوظ على هذا الجهاز. استخدم تسجيل الدخول الكامل.')}
}
function hasPasskeySupport(){
 return !!(navigator.credentials?.create&&navigator.credentials?.get&&
  typeof PublicKeyCredential!=='undefined'&&crypto?.subtle);
}
async function passkeyKey(prfOutput){
 if(!prfOutput||new Uint8Array(prfOutput).length!==32)
  throw Error('متصفحك لم يوفّر مفتاح PRF المطلوب لحماية الدخول ببصمة الجهاز.');
 const material=await crypto.subtle.importKey('raw',prfOutput,'HKDF',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',
  salt:ENC.encode('masareefi-device-passkey-v22'),info:ENC.encode('masareefi-financial-vault')},
  material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function passkeyOutput(credential,first){
 const results=credential?.getClientExtensionResults?.();
 const value=results?.prf?.results?.first;
 return value&&new Uint8Array(value).length===32?value:null;
}
async function createPasskey(secrets){
 const verified=verifySecrets(secrets);
 if(!hasPasskeySupport())throw Error('بصمة الوجه/رمز الجهاز عبر Passkeys غير مدعوم في هذا المتصفح.');
 const salt=random(32);
 const created=await navigator.credentials.create({publicKey:{
  challenge:random(32),
  rp:{name:'مصاريفي',id:location.hostname},
  user:{id:random(24),name:verified.email,displayName:'مصاريفي — '+verified.email},
  pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
  authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'required',userVerification:'required'},
  timeout:60000,attestation:'none',extensions:{prf:{eval:{first:salt}}}
 }});
 if(!created?.rawId)throw Error('لم يتم إنشاء بصمة الدخول.');
 let output=await passkeyOutput(created,salt);
 if(!output){
  const checked=await navigator.credentials.get({publicKey:{
   challenge:random(32),allowCredentials:[{type:'public-key',id:created.rawId}],
   userVerification:'required',timeout:60000,extensions:{prf:{eval:{first:salt}}}
  }});
  if(!checked||toB64(new Uint8Array(checked.rawId))!==toB64(new Uint8Array(created.rawId)))
   throw Error('تعذّر التحقق من بصمة الدخول.');
  output=await passkeyOutput(checked,salt);
 }
 if(!output)throw Error('هذا المتصفح لا يتيح تشفير الاتصال ببصمة الجهاز (PRF). لم تُفعّل الميزة.');
 const key=await passkeyKey(output);
 const record=await seal({...rowFor(verified,'passkey'),credentialId:toB64(new Uint8Array(created.rawId)),salt:toB64(salt)},verified,key);
 await putVault(record,null);
 return true;
}
async function unlockPasskey(){
 const record=await getRecord(STORE,CURRENT);
 if(!record||record.mode!=='passkey')throw Error('لم يتم تفعيل الدخول ببصمة الجهاز.');
 if(!hasPasskeySupport())throw Error('المتصفح الحالي لا يدعم بصمة الجهاز.');
 const credential=await navigator.credentials.get({publicKey:{
  challenge:random(32),allowCredentials:[{type:'public-key',id:fromB64(record.credentialId)}],
  userVerification:'required',timeout:60000,
  extensions:{prf:{eval:{first:fromB64(record.salt)}}}
 }});
 if(!credential||toB64(new Uint8Array(credential.rawId))!==record.credentialId)
  throw Error('البصمة المستخدمة ليست البصمة المسجلة لهذا التطبيق.');
 const output=await passkeyOutput(credential);
 const key=await passkeyKey(output);
 try{return await unseal(record,key)}
 catch(_){throw Error('تعذر فك اتصال مصاريفي باستخدام بصمة الجهاز. استخدم تسجيل الدخول الكامل.')}
}
window.masareefiDeviceVaultV22={
 metadata,clear,rememberAutomatic,restoreAutomatic,createPasskey,unlockPasskey,
 available,hasPasskeySupport
};
})();
