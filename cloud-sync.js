/* Masareefi 2.0 — v21 encrypted financial cloud sync (opt-in, Firebase REST).
 * Does NOT upload attachments, card messages, passwords, or credentials to GitHub.
 * Cloud transactions are encrypted with AES-GCM + PBKDF2 using a session-only phrase.
 */
(function(){
'use strict';
const CONFIG_KEY='masareefi_finance_sync_v19';
const LOCK_KEY='masareefi_finance_sync_v21_encrypted_unlock';
const CHUNK_SIZE=380000;
const MAX_DATA_BYTES=8*1024*1024;
const MAX_PARTS=32;
const ENC=new TextEncoder(),DEC=new TextDecoder();
const E=id=>document.getElementById(id);
const statusText=message=>{const node=E('syncStatusV19');if(node)node.textContent=message};
const session={projectId:'',apiKey:'',email:'',uid:'',idToken:'',refreshToken:'',expiry:0,phrase:'',active:false,busy:false,applying:false,pending:false,base:null,timer:null,remembered:false,showLoginForm:false,unlockBusy:false,notice:'لم يتم ربط الحساب السحابي بعد.'};
const savedConfig=readConfig();
function readConfig(){
 try{const raw=JSON.parse(localStorage.getItem(CONFIG_KEY)||'{}');return raw&&typeof raw==='object'?raw:{}}catch(e){return {}}
}
function saveConfig(){
 localStorage.setItem(CONFIG_KEY,JSON.stringify({projectId:session.projectId,apiKey:session.apiKey,email:session.email}));
}

function readLock(){
 try{
  const x=JSON.parse(localStorage.getItem(LOCK_KEY)||'null');
  return x&&x.version===1&&typeof x.projectId==='string'&&typeof x.email==='string'&&
   typeof x.uid==='string'&&typeof x.salt==='string'&&typeof x.iv==='string'&&
   typeof x.content==='string'&&x.content.length<10000?x:null;
 }catch(_){return null}
}
function clearLock(){localStorage.removeItem(LOCK_KEY);session.remembered=false;}
async function saveSessionLock(){
 if(!session.remembered||!session.refreshToken||!session.phrase)return;
 const raw=JSON.stringify({projectId:session.projectId,email:session.email,uid:session.uid,refreshToken:session.refreshToken});
 const encrypted=await encryptSnapshot(raw,session.phrase);
 localStorage.setItem(LOCK_KEY,JSON.stringify({version:1,projectId:session.projectId,
  email:session.email,uid:session.uid,salt:encrypted.salt,iv:encrypted.iv,content:encrypted.content}));
}
async function unlockSession(phrase){
 const lock=readLock(),config=readConfig();
 if(!lock)throw Error('لا يوجد اتصال محفوظ على هذا الجهاز.');
 if(phrase.length<12)throw Error('عبارة التشفير يجب ألا تقل عن 12 حرفًا.');
 if(config.projectId!==lock.projectId||config.email!==lock.email||!config.apiKey)
  throw Error('إعدادات Firebase تغيرت. سجّل الدخول الكامل من جديد.');
 let saved;
 try{saved=JSON.parse(await decryptSnapshot(lock.content,phrase,lock.salt,lock.iv))}
 catch(_){throw Error('عبارة التشفير غير مطابقة أو بيانات الاتصال تالفة. يمكنك استخدام تسجيل الدخول الكامل.')}
 if(!saved||saved.projectId!==lock.projectId||saved.email!==lock.email||
    saved.uid!==lock.uid||typeof saved.refreshToken!=='string'||saved.refreshToken.length<20)
  throw Error('بيانات الاتصال المحفوظة غير صالحة. استخدم تسجيل الدخول الكامل.');
 session.projectId=lock.projectId;session.apiKey=config.apiKey;session.email=lock.email;
 session.uid=lock.uid;session.idToken='';session.refreshToken=saved.refreshToken;
 session.expiry=0;session.phrase=phrase;session.remembered=true;
 session.base=readBase();session.active=!!session.base?.hash;
 try{await authToken()}
 catch(e){
  session.uid='';session.idToken='';session.refreshToken='';session.phrase='';session.active=false;
  throw Error('تعذّر تجديد الجلسة. استخدم تسجيل الدخول الكامل: '+String(e.message||e));
 }
 setNotice('جارٍ مقارنة النسختين بعد فتح الاتصال المحفوظ…');
 await synchronize(false);
}

function saveBase(value){
 if(!session.uid)return;
 localStorage.setItem(CONFIG_KEY+'_baseline_'+session.projectId+'_'+session.uid,JSON.stringify(value));
 session.base=value;
}
function readBase(){
 if(!session.uid)return null;
 try{return JSON.parse(localStorage.getItem(CONFIG_KEY+'_baseline_'+session.projectId+'_'+session.uid)||'null')}catch(e){return null}
}
function stableStringify(value){
 function sort(obj){
  if(Array.isArray(obj))return obj.map(sort);
  if(obj&&typeof obj==='object'){
   return Object.fromEntries(Object.keys(obj).sort().filter(k=>obj[k]!==undefined&&k!=='_receiptBackup').map(k=>[k,sort(obj[k])]));
  }
  return obj;
 }
 return JSON.stringify(sort(value));
}
function bytesToB64(bytes){
 let result='';
 for(let i=0;i<bytes.length;i+=0x8000)result+=String.fromCharCode(...bytes.subarray(i,i+0x8000));
 return btoa(result);
}
function b64ToBytes(encoded){
 const str=atob(encoded);const bytes=new Uint8Array(str.length);
 for(let i=0;i<str.length;i++)bytes[i]=str.charCodeAt(i);
 return bytes;
}
async function digest(text){
 const bytes=await crypto.subtle.digest('SHA-256',ENC.encode(text));
 return [...new Uint8Array(bytes)].map(c=>c.toString(16).padStart(2,'0')).join('');
}
async function deriveKey(phrase,salt){
 const secret=await crypto.subtle.importKey('raw',ENC.encode(phrase),'PBKDF2',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:250000,hash:'SHA-256'},secret,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function encryptSnapshot(plain,phrase){
 const salt=crypto.getRandomValues(new Uint8Array(16));
 const iv=crypto.getRandomValues(new Uint8Array(12));
 const key=await deriveKey(phrase,salt);
 const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,ENC.encode(plain)));
 return {content:bytesToB64(encrypted),salt:bytesToB64(salt),iv:bytesToB64(iv)};
}
async function decryptSnapshot(cipher,phrase,salt64,iv64){
 const salt=b64ToBytes(salt64),iv=b64ToBytes(iv64);
 if(salt.length!==16||iv.length!==12)throw Error('بيانات التشفير السحابي غير صالحة');
 const key=await deriveKey(phrase,salt);
 const decrypted=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,b64ToBytes(cipher));
 return DEC.decode(decrypted);
}
function firebaseError(code){
 const names={
  INVALID_LOGIN_CREDENTIALS:'البريد الإلكتروني أو كلمة المرور غير صحيحة.',
  EMAIL_NOT_FOUND:'البريد الإلكتروني غير موجود في مشروع Firebase.',
  INVALID_PASSWORD:'كلمة المرور غير صحيحة.',
  OPERATION_NOT_ALLOWED:'فعّل تسجيل الدخول بالبريد وكلمة المرور في Firebase Authentication.',
  PERMISSION_DENIED:'صلاحيات Firestore تمنع الوصول. تأكد من تفعيل قواعد الأمان.',
  RESOURCE_EXHAUSTED:'تجاوزت الحصة المسموحة لخدمة Firebase.',
  UNAUTHENTICATED:'انتهت الجلسة أو لا يمكن التحقق منها.',
  FAILED_PRECONDITION:'تغيّرت النسخة السحابية أثناء المزامنة. لن نستبدل بيانات الجهاز الآخر.',
  NOT_FOUND:'لم يُعثر على البيانات المطلوبة.'
 };
 const raw=String(code||'خطأ غير معروف').split(':')[0].trim();
 return names[raw]||'تعذر الاتصال بخدمة Firebase: '+raw.slice(0,100);
}
async function request(url,options={}){
 const controller=new AbortController();
 const timeout=setTimeout(()=>controller.abort(),20000);
 try{
  const response=await fetch(url,{cache:'no-store',...options,signal:controller.signal});
  let payload={};
  try{payload=await response.json()}catch(e){}
  if(response.status===404&&options.allow404)return null;
  if(!response.ok){
   const err=new Error(firebaseError(payload?.error?.status||payload?.error?.message||response.status));
   err.status=response.status;throw err;
  }
  return payload;
 }catch(e){
  if(e.name==='AbortError')throw Error('انتهت مهلة الاتصال. تحقق من الإنترنت وحاول مجددًا.');
  throw e;
 }finally{clearTimeout(timeout)}
}
async function authToken(){
 if(!session.refreshToken||!session.uid)throw Error('يرجى تسجيل الدخول إلى المزامنة أولًا.');
 if(session.idToken&&Date.now()+90000<session.expiry)return session.idToken;
 const url='https://securetoken.googleapis.com/v1/token?key='+encodeURIComponent(session.apiKey);
 const body=new URLSearchParams({grant_type:'refresh_token',refresh_token:session.refreshToken}).toString();
 const answer=await request(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
 session.idToken=answer.id_token;
 if(answer.user_id&&answer.user_id!==session.uid)throw Error('هوية Firebase المستعادة غير مطابقة.');
 const rotated=!!answer.refresh_token&&answer.refresh_token!==session.refreshToken;
 session.refreshToken=answer.refresh_token||session.refreshToken;
 session.expiry=Date.now()+(Number(answer.expires_in)||3600)*1000;
 if(rotated&&session.remembered){
  try{await saveSessionLock()}catch(_){clearLock()}
 }
 return session.idToken;
}
async function signIn(projectId,apiKey,email,password,phrase,rememberDevice=false){
 if(!/^[a-z][a-z0-9-]{3,60}$/.test(projectId))throw Error('معرّف مشروع Firebase غير صحيح.');
 if(apiKey.length<15||apiKey.length>200)throw Error('أدخل Web API Key الصحيح من Firebase.');
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))throw Error('أدخل بريدًا إلكترونيًا صالحًا.');
 if(phrase.length<12)throw Error('عبارة التشفير يجب أن تحتوي 12 حرفًا على الأقل؛ لا تفقدها.');
 const url='https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key='+encodeURIComponent(apiKey);
 const user=await request(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password,returnSecureToken:true})});
 if(!user.localId||!user.idToken||!user.refreshToken)throw Error('لم تكتمل المصادقة.');
 session.projectId=projectId;
 session.apiKey=apiKey;
 session.email=email;
 session.uid=user.localId;
 session.idToken=user.idToken;
 session.refreshToken=user.refreshToken;
 session.expiry=Date.now()+(Number(user.expiresIn)||3600)*1000;
 session.phrase=phrase;
 session.base=readBase();
 session.active=!!session.base?.hash;
 session.remembered=false;
 saveConfig();
 try{await validateCloudPassphrase()}
 catch(e){
  session.uid='';session.idToken='';session.refreshToken='';session.phrase='';
  session.active=false;session.base=null;
  throw e;
 }
 session.remembered=!!rememberDevice;
 let failedToRemember=false;
 if(session.remembered){
  try{await saveSessionLock()}catch(_){clearLock();failedToRemember=true}
 }else clearLock();
 statusText('تم تسجيل الدخول. جارٍ مقارنة السجلات المحلية والسحابية…');
 await synchronize(false);
 if(failedToRemember)setNotice(session.notice+' ⚠ تعذر حفظ الاتصال المشفر على الجهاز؛ ستحتاج إلى تسجيل الدخول الكامل عند إعادة الفتح.');
}
function pathFor(collection,id){
 const p=session.projectId,u=session.uid;
 if(!/^[a-z][a-z0-9-]{3,60}$/.test(p)||!/^[a-zA-Z0-9:_-]{6,128}$/.test(u))throw Error('معرّف حساب Firebase غير صالح');
 if(!/^[a-zA-Z0-9_-]{1,128}$/.test(id))throw Error('معرّف نسخة غير صالح');
 return 'projects/'+p+'/databases/(default)/documents/users/'+u+'/'+collection+'/'+id;
}
function docUrl(collection,id){
 return 'https://firestore.googleapis.com/v1/'+pathFor(collection,id);
}
async function firestore(collection,id,method='GET',fields=null,precondition=null){
 const token=await authToken();
 const url=new URL(docUrl(collection,id));
 if(precondition){
  if(precondition.exists===false)url.searchParams.set('currentDocument.exists','false');
  else if(precondition.updateTime)url.searchParams.set('currentDocument.updateTime',precondition.updateTime);
 }
 const args={method,headers:{Authorization:'Bearer '+token},allow404:method==='GET'};
 if(fields!==null){
  args.headers['Content-Type']='application/json';
  args.body=JSON.stringify({name:pathFor(collection,id),fields});
 }
 return request(url.toString(),args);
}
function fieldsOf(manifest){
 if(!manifest)return null;
 const fields=manifest.fields||{};
 const get=k=>fields[k]?.stringValue;
 const num=k=>Number(fields[k]?.integerValue||0);
 const entry={revision:get('revision'),hash:get('hash'),salt:get('salt'),iv:get('iv'),
  parts:num('parts'),format:num('format'),updateTime:manifest.updateTime||'',size:num('size')};
 if(entry.format!==1||!entry.revision||!entry.hash||!entry.salt||!entry.iv||
   !/^[a-zA-Z0-9_-]{12,70}$/.test(entry.revision)||
   !/^[a-f0-9]{64}$/.test(entry.hash)||entry.parts<1||entry.parts>MAX_PARTS||
   entry.size<1||entry.size>MAX_DATA_BYTES*2)throw Error('بيانات النسخة السحابية لا تطابق تنسيق المزامنة.');
 return entry;
}
async function readManifest(){return fieldsOf(await firestore('sync','meta'))}
async function currentHash(){return digest(stableStringify(data))}
function nonempty(){
 return ['transactions','savings','receivables','debts','goals','recurringIncome'].some(k=>Array.isArray(data[k])&&data[k].length>0)||
  Object.keys(data.budgets||{}).length>0;
}
function selectedUI(){
 const modal=document.querySelector('#modal[open]');
 const syncDialog=!!(modal&&E('syncCurrentStatusV19'));
 const editing=!!document.querySelector('#entryFullV13[open],#smartPasteDialog[open]')||
  !!(modal&&!syncDialog);
 const focused=document.activeElement;
 const writing=!!focused&&typeof focused.matches==='function'&&
  focused.matches('input,textarea,select')&&!(syncDialog&&modal.contains(focused));
 return editing||writing;
}
function classification(remoteHash,localHash,baselineHash){
 if(!remoteHash)return baselineHash?'conflict':'empty';
 if(remoteHash===localHash)return 'equal';
 if(!baselineHash)return 'conflict';
 if(remoteHash===baselineHash)return 'upload';
 if(localHash===baselineHash)return 'download';
 return 'conflict';
}
function describeRemote(remote,localHash){
 if(!remote)return 'لا توجد نسخة سحابية لهذا الحساب. يمكنك رفع النسخة المحلية للمرة الأولى.';
 if(remote.hash===localHash)return 'البيانات المحلية والسحابية متطابقة.';
 return 'هناك اختلاف بين الجهاز والسحابة. سنقارن النسختين دون استبدال صامت.';
}
function summaryV20(){
 const box=E('syncConnectionSummaryV20');
 if(!box)return;
 const msg=session.notice||'';
 const kind=!session.uid?'offline':msg.includes('تعارض')||msg.includes('⚠')?'conflict':
  msg.startsWith('تعذرت')?'error':!session.active?'attention':
  msg.includes('جارٍ')?'syncing':msg.includes('بانتظار')?'pending':'connected';
 box.dataset.syncState=kind;
 if(!session.uid){
  box.textContent='🔒 '+(msg.includes('تم حفظ التعديل على هذا الجهاز فقط')?'تعديل محلي لم يُزامن بعد. ':'')+
   (readLock()?'الاتصال محفوظ مشفرًا؛ افتح المزامنة وأدخل عبارة التشفير لتفعيله.':
    'المزامنة غير متصلة. سجّل الدخول قبل توقع انتقال التعديلات.');
 }else box.textContent=(kind==='connected'?'✓ ':kind==='syncing'?'↻ ':'⚠ ')+msg+
  (session.remembered?' · يمكنك فتح الاتصال لاحقًا بعبارة التشفير فقط.':'');
}
function refreshStatus(){
 summaryV20();
 const n=E('syncCurrentStatusV19');
 if(n)n.textContent=session.notice;
 const linked=E('syncAccountLabelV19');
 if(linked)linked.textContent=session.uid?'متصل: '+session.email:'غير متصل';
 const connected=E('syncConnectedControlsV19');
 if(connected)connected.hidden=!session.uid;
 const inactive=E('syncLoginPanelV19'),unlock=E('syncUnlockPanelV21');
 const saved=!!readLock();
 if(inactive)inactive.hidden=!!session.uid||(saved&&!session.showLoginForm);
 if(unlock)unlock.hidden=!!session.uid||!saved||session.showLoginForm;
 const hint=E('syncRememberedHintV21');
 if(hint)hint.textContent=session.remembered?'✓ اتصال هذا الجهاز محفوظ بشكل مشفر، ويمكن فتحه لاحقًا بعبارة التشفير.':
 'هذا الاتصال مفعّل في الجلسة الحالية فقط؛ يلزم تسجيل الدخول عند إعادة فتح التطبيق.';
 const rememberButton=E('syncRememberDeviceV21');
 if(rememberButton)rememberButton.textContent=session.remembered?'إلغاء تذكّر هذا الجهاز':'تذكّر هذا الجهاز';
}
function setNotice(msg){session.notice=msg;statusText(msg);refreshStatus()}
function holdTimer(){if(session.timer)clearTimeout(session.timer);session.timer=null}
async function readSnapshot(manifest){
 const chunks=[];
 for(let i=0;i<manifest.parts;i++){
  const obj=await firestore('sync_chunks',manifest.revision+'_'+String(i));
  const info=obj?.fields;
  if(!info||info.revision?.stringValue!==manifest.revision||
    Number(info.part?.integerValue)!==i||
    typeof info.payload?.stringValue!=='string'||
    info.payload.stringValue.length>CHUNK_SIZE)throw Error('جزء مفقود أو تالف من النسخة السحابية.');
  chunks.push(info.payload.stringValue);
 }
 const plain=await decryptSnapshot(chunks.join(''),session.phrase,manifest.salt,manifest.iv);
 if(ENC.encode(plain).length>MAX_DATA_BYTES)throw Error('حجم السجل المالي السحابي يتجاوز الحد المتاح.');
 if(await digest(plain)!==manifest.hash)throw Error('لم يتطابق التوقيع الرقمي للسجل.');
 const parsed=JSON.parse(plain);
 if(!parsed||typeof parsed!=='object'||!Array.isArray(parsed.transactions)||
   !Array.isArray(parsed.savings)||!Array.isArray(parsed.receivables))throw Error('نسخة البيانات السحابية غير صالحة.');
 return parsed;
}
async function validateCloudPassphrase(){
 // Verify the phrase can authenticate and decrypt the existing cloud snapshot.
 // Never change local/cloud records in this check.
 const manifest=await readManifest();
 if(!manifest)return;
 try{await readSnapshot(manifest)}
 catch(e){
  if(e?.name==='OperationError'||/decrypt|decrypting|operation-specific/i.test(String(e?.message||'')))
   throw Error('عبارة التشفير لا تطابق السجلات المشفرة في Firebase. استخدم نفس العبارة السابقة؛ لم نغيّر أي بيانات.');
  throw e;
 }
}

async function adoptRemote(manifest,auto=false){
 if(auto&&selectedUI()){setNotice('توجد نسخة سحابية جديدة؛ سيتم استلامها عند إغلاق محرر العملية أو الضغط على «مزامنة الآن».');return}
 const originalHash=await currentHash();
 const received=await readSnapshot(manifest);
 if(auto&&(selectedUI()||(await currentHash())!==originalHash)){
  session.pending=true;
  setNotice('تغيّرت بيانات هذا الجهاز أثناء تنزيل النسخة؛ أوقفنا الاستبدال لحمايتها.');
  return;
 }
 // An encrypted cloud snapshot contains only financial JSON. Receipts remain in IndexedDB.
 const oldData=data;
 session.applying=true;
 try{
  data=hydrate(received);
  localStorage.setItem(KEY,JSON.stringify(data));
  render();
  saveBase({hash:manifest.hash,revision:manifest.revision,updateTime:manifest.updateTime});
  session.active=true;
  setNotice('✓ تم تنزيل السجلات المالية المشفرة وتحديثها على هذا الجهاز. المرفقات تُنقل بالنسخة الاحتياطية اليدوية.');
 }catch(e){
  data=oldData;
  try{render()}catch(_){}
  throw e;
 }finally{session.applying=false}
}
async function uploadSnapshot(existing){
 const json=stableStringify(data);
 const bytes=ENC.encode(json);
 if(bytes.length>MAX_DATA_BYTES)throw Error('السجل المالي كبير جدًا للمزامنة الحالية (8 ميجابايت). استخدم النسخ الاحتياطي اليدوي.');
 const hash=await digest(json);
 if(existing?.hash===hash){
  saveBase({hash,revision:existing.revision,updateTime:existing.updateTime});
  session.active=true;setNotice('✓ البيانات متطابقة؛ لا توجد تغييرات للرفع.');
  return;
 }
 const enc=await encryptSnapshot(json,session.phrase);
 const parts=[];
 for(let i=0;i<enc.content.length;i+=CHUNK_SIZE)parts.push(enc.content.slice(i,i+CHUNK_SIZE));
 if(!parts.length||parts.length>MAX_PARTS)throw Error('حجم النسخة المشفرة تجاوز الحد المتاح لهذه المرحلة.');
 const revision=crypto.randomUUID().replace(/-/g,'');
 // Upload immutable chunks first; only after all succeed publish the new manifest.
 for(let i=0;i<parts.length;i++){
  await firestore('sync_chunks',revision+'_'+String(i),'PATCH',{
   revision:{stringValue:revision},part:{integerValue:String(i)},payload:{stringValue:parts[i]}
  },{exists:false});
 }
 const fields={
  revision:{stringValue:revision},hash:{stringValue:hash},
  salt:{stringValue:enc.salt},iv:{stringValue:enc.iv},
  parts:{integerValue:String(parts.length)},format:{integerValue:'1'},
  size:{integerValue:String(bytes.length)},updatedAt:{timestampValue:new Date().toISOString()}
 };
 const current=await firestore('sync','meta','PATCH',fields,existing?{updateTime:existing.updateTime}:{exists:false});
 if(!current?.updateTime)throw Error('لم تؤكد السحابة حفظ النسخة الجديدة.');
 saveBase({hash,revision,updateTime:current.updateTime});
 session.active=true;
 setNotice('✓ تمت مزامنة البيانات المالية المشفرة بنجاح. '+new Date().toLocaleTimeString('ar-SA',{hour:'2-digit',minute:'2-digit'}));
}
async function synchronize(force,choice=''){
 if(!session.uid)return setNotice('سجّل الدخول أولًا إلى حساب المزامنة.');
 if(session.busy)return;
 if(!navigator.onLine)return setNotice('لا يوجد اتصال حاليًا؛ بياناتك محفوظة على الجهاز. أعد الاتصال لإتمام المزامنة.');
 holdTimer();session.busy=true;setNotice('جارٍ التحقق من نسخة السحابة…');
 try{
  const localHash=await currentHash();
  const remote=await readManifest();
  const remoteHash=remote?.hash||null;
  const action=classification(remoteHash,localHash,session.base?.hash);
  if(choice==='upload'){
   if(!force)throw Error('الرفع الذي يستبدل النسخة السحابية يحتاج إلى تأكيد صريح.');
   await uploadSnapshot(remote);
  }else if(choice==='download'){
   if(!remote)throw Error('لا توجد نسخة سحابية قابلة للتنزيل.');
   if(!force)throw Error('استبدال النسخة المحلية يحتاج إلى تأكيد صريح.');
   await adoptRemote(remote);
  }else if(action==='equal'){
   saveBase({hash:localHash,revision:remote.revision,updateTime:remote.updateTime});
   session.active=true;setNotice('✓ البيانات متطابقة بين الجهاز والسحابة؛ المزامنة التلقائية مفعّلة أثناء فتح التطبيق.');
  }else if(action==='upload'&&session.active){
   await uploadSnapshot(remote);
  }else if(action==='download'&&session.active){
   await adoptRemote(remote,true);
  }else if(action==='empty'){
   session.active=false;
   setNotice('الحساب السحابي جديد. اضغط «رفع بيانات هذا الجهاز» لتأسيس النسخة الأولى بعد مراجعة سجلاتك.');
  }else{
   session.active=false;
   setNotice('⚠ تعارض بين نسختين أو جهاز جديد. لا يتم الدمج أو الحذف تلقائيًا. احفظ نسخة JSON كاملة، ثم اختر رفع الجهاز أو استلام السحابة يدويًا.');
  }
 }catch(e){
  if(e.status===409||e.status===412){
   session.active=false;setNotice('⚠ تم تحديث السحابة من جهاز آخر أثناء الرفع؛ لم نكتب فوقه. راجع التعارض.');
  }else setNotice('تعذرت المزامنة: '+String(e.message||e).slice(0,170));
 }finally{
  session.busy=false;
  refreshStatus();
  if(session.pending&&session.active){session.pending=false;schedule()}
 }
}
function schedule(){
 if(!session.uid||!session.active||session.applying||session.busy)return;
 holdTimer();
 setNotice('تغييرات محلية بانتظار الرفع الآمن…');
 session.timer=setTimeout(()=>{session.timer=null;synchronize(false)},2400);
}
function onPersist(){
 if(session.applying)return;
 if(!session.uid||!session.active){
  if(!session.uid&&readConfig().email)session.notice='تم حفظ التعديل على هذا الجهاز فقط. سجّل الدخول مجددًا لتفعيل المزامنة.';
  else if(session.uid&&!session.active)session.notice='التعديل محفوظ محليًا؛ المزامنة متوقفة حتى مراجعة حالة السحابة.';
  summaryV20();
  return;
 }
 if(session.busy){session.pending=true;return}
 schedule();
}
function disconnect(){
 holdTimer();
 session.idToken='';session.refreshToken='';session.phrase='';session.uid='';
 session.active=false;session.base=null;session.busy=false;session.pending=false;
 clearLock();session.showLoginForm=false;
 setNotice('تم قطع الاتصال ومسح وسيلة استعادته من هذا المتصفح؛ السجلات المالية لم تُحذف.');
}
function openSettings(){
 const config=readConfig();
 const html='<p class="footnote">مزامنة مشفرة للعمليات والدخل والادخار والديون والتصنيفات بين أجهزتك، عبر Firebase خاص بك. <b>صور الفواتير وPDF لا تتزامن هنا</b> وتبقى ضمن النسخ الاحتياطية الشاملة.</p>'+
  '<div id="syncUnlockPanelV21" hidden>'+
   '<p class="footnote">هذا الجهاز يحفظ وسيلة اتصال مشفرة بعبارة التشفير، وليس كلمة مرور Firebase أو العبارة نفسها. أدخل العبارة لتفعيل المزامنة أثناء فتح التطبيق.</p>'+
   '<form id="syncUnlockFormV21"><div class="field"><label>عبارة التشفير</label><input name="unlockPhrase" type="password" minlength="12" required autocomplete="off"></div>'+
    '<button class="btn" type="submit">فتح الاتصال المشفر</button></form>'+
   '<div class="actions"><button type="button" class="btn outline" id="syncShowFullLoginV21">تسجيل الدخول الكامل</button>'+
    '<button type="button" class="btn outline" id="syncForgetDeviceV21">نسيان هذا الجهاز</button></div>'+
  '</div>'+
  '<div id="syncLoginPanelV19">'+
   '<form id="syncLoginFormV19">'+
    '<div class="field"><label>معرّف مشروع Firebase</label><input name="projectId" dir="ltr" required autocomplete="off" value="'+safe(config.projectId||'')+'" placeholder="my-finance-project"></div>'+
    '<div class="field"><label>Web API Key (معرّف عام للمشروع، ليس كلمة مرور)</label><input name="apiKey" dir="ltr" required autocomplete="off" value="'+safe(config.apiKey||'')+'"></div>'+
    '<div class="field"><label>البريد الإلكتروني في Firebase Authentication</label><input name="email" type="email" required autocomplete="username" value="'+safe(config.email||'')+'"></div>'+
    '<div class="field"><label>كلمة مرور الحساب</label><input name="password" type="password" required autocomplete="current-password"></div>'+
    '<div class="field"><label>عبارة التشفير الخاصة بك (12 حرفًا على الأقل)</label><input name="phrase" type="password" minlength="12" required autocomplete="off" placeholder="استخدم نفس العبارة على كل أجهزتك"></div>'+
    '<label class="field" style="display:flex;gap:10px;align-items:flex-start;line-height:1.8"><input type="checkbox" name="rememberDevice" style="flex:0 0 auto;margin-top:5px"><span>تذكّر هذا الجهاز باتصال مشفّر؛ سأدخل عبارة التشفير فقط عند إعادة فتح مصاريفي (اختياري).</span></label>'+
    '<p class="footnote">لا تُرفع كلمات المرور أو عبارة التشفير إلى GitHub. خيار تذكّر الجهاز يحفظ رمز تجديد Firebase مشفرًا محليًا؛ فقدان عبارة التشفير يمنع قراءة النسخ السحابية القديمة.</p>'+
    '<button class="btn" type="submit">ربط حسابي السحابي</button>'+
   '</form></div>'+
  '<div id="syncConnectedControlsV19" hidden>'+
   '<p id="syncAccountLabelV19" class="footnote"></p>'+
   '<p id="syncRememberedHintV21" class="footnote"></p>'+
   '<div class="actions"><button type="button" id="syncNowV19" class="btn">مزامنة الآن</button>'+
   '<button type="button" id="syncRememberDeviceV21" class="btn outline">تذكّر هذا الجهاز</button>'+
   '<button type="button" id="syncPushV19" class="btn secondary">رفع بيانات هذا الجهاز</button>'+
   '<button type="button" id="syncPullV19" class="btn outline">استلام البيانات من السحابة</button>'+
   '<button type="button" id="syncDisconnectV19" class="btn outline">قطع الاتصال</button></div>'+
   '<p class="footnote">أثناء تشغيل التطبيق وبعد فتح الاتصال، تُرفع التغييرات تلقائيًا ويُفحص وجود تحديثات كل 45 ثانية تقريبًا أو عند العودة للتطبيق. لا تحدث مزامنة وهو مغلق تمامًا على الآيفون. عند وجود تعارض نوقف المزامنة ولا نستبدل أي نسخة تلقائيًا.</p>'+
   '<p class="footnote">قبل اختيار رفع أو استلام عند التعارض، احفظ <b>نسخة JSON شاملة مع المرفقات</b> من صفحة النسخ الاحتياطي.</p>'+
  '</div>'+
  '<p id="syncCurrentStatusV19" class="sync-state-v19" role="status"></p>'+
  '<p class="footnote"><a href="https://github.com/ashrafv2/asareefi-test/blob/main/FIREBASE_SYNC_SETUP_AR.md" target="_blank" rel="noopener noreferrer">دليل إنشاء مشروع Firebase وتفعيل قواعد الأمان</a></p>';
 openModal('المزامنة المالية المشفرة',html,function(){
  session.showLoginForm=!readLock();
  refreshStatus();
  E('syncShowFullLoginV21').onclick=()=>{session.showLoginForm=true;refreshStatus()};
  E('syncForgetDeviceV21').onclick=()=>{
   if(!confirm('سيتم حذف وسيلة الاتصال المشفرة المحفوظة محليًا فقط. لن تُحذف السجلات ولا بيانات Firebase. متابعة؟'))return;
   clearLock();session.showLoginForm=true;
   setNotice('تم نسيان الاتصال المحفوظ. يمكنك تسجيل الدخول من جديد.');
  };
  E('syncUnlockFormV21').onsubmit=async event=>{
   event.preventDefault();
   if(session.unlockBusy)return;
   const frm=event.currentTarget,btn=frm.querySelector('button[type="submit"]');
   session.unlockBusy=true;btn.disabled=true;setNotice('جارٍ فتح الاتصال المشفر…');
   try{await unlockSession(frm.elements.unlockPhrase.value);frm.elements.unlockPhrase.value=''}
   catch(e){setNotice('تعذر فتح الاتصال: '+String(e.message||e))}
   finally{session.unlockBusy=false;btn.disabled=false;refreshStatus()}
  };
  E('syncLoginFormV19').onsubmit=async event=>{
   event.preventDefault();
   const frm=event.currentTarget;
   const submit=frm.querySelector('button[type="submit"]');
   submit.disabled=true;
   setNotice('جارٍ ربط الحساب…');
   try{
    await signIn(frm.elements.projectId.value.trim(),frm.elements.apiKey.value.trim(),frm.elements.email.value.trim(),
      frm.elements.password.value,frm.elements.phrase.value,frm.elements.rememberDevice.checked);
    frm.elements.password.value='';frm.elements.phrase.value='';
   }catch(e){setNotice(String(e.message||e));}
   finally{submit.disabled=false;refreshStatus()}
  };
  E('syncNowV19').onclick=()=>synchronize(true);
  E('syncRememberDeviceV21').onclick=async()=>{
   if(!session.uid||!session.phrase)return setNotice('سجّل الدخول أولًا لتذكّر هذا الجهاز.');
   if(session.remembered){
    clearLock();setNotice('تم إلغاء تذكّر هذا الجهاز؛ المزامنة الحالية مستمرة ما دام التطبيق مفتوحًا.');
    return;
   }
   if(!confirm('سيُحفظ رمز تجديد حساب Firebase مشفرًا بعبارة التشفير في هذا المتصفح فقط. عند فتح التطبيق ستحتاج إلى إدخال العبارة. هل تريد تذكّر هذا الجهاز؟'))return;
   session.remembered=true;
   try{await saveSessionLock();setNotice('✓ تذكّر هذا الجهاز مفعّل. سيُطلب إدخال عبارة التشفير فقط بعد إعادة فتح التطبيق.')}
   catch(_){clearLock();setNotice('تعذر حفظ الاتصال المشفر في هذا المتصفح. سيبقى الاتصال الحالي فقط.')}
  };
  E('syncPushV19').onclick=()=>{
   if(!confirm('سيتم رفع سجل هذا الجهاز واستبدال النسخة السحابية الحالية إن وجدت. تأكد من تنزيل نسخة احتياطية شاملة أولًا. هل تريد المتابعة؟'))return;
   synchronize(true,'upload');
  };
  E('syncPullV19').onclick=()=>{
   if(!confirm('سيتم استبدال جميع سجلاتك المالية المحلية بالنسخة السحابية. المرفقات الموجودة على الجهاز لا تُحذف، لكنها قد لا تطابق العمليات الجديدة. احفظ نسخة احتياطية شاملة أولًا. متابعة؟'))return;
   synchronize(true,'download');
  };
  E('syncDisconnectV19').onclick=disconnect;
 });
}
E('financeSyncSettingsV19')?.addEventListener('click',openSettings);
window.masareefiSyncV19={onPersist,openSettings,synchronize,stableStringify,classification,disconnect};
window.addEventListener('online',()=>{if(session.uid&&session.active)schedule()});
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'&&session.uid&&session.active)synchronize(false)});
window.addEventListener('focus',()=>{if(session.uid&&session.active)synchronize(false)});
window.addEventListener('pageshow',()=>{if(session.uid&&session.active)synchronize(false)});
setInterval(()=>{if(session.uid&&session.active&&document.visibilityState==='visible')synchronize(false)},45000);
summaryV20();
})();
