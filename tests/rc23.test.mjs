/**
 * Masareefi 2.0 RC23 — read-only source regression tests + isolated mock login.
 * Run: node --test tests/rc23.test.mjs
 * Never reads browser storage, real Firebase or financial data.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import { TextEncoder, TextDecoder } from 'node:util';

const read=name=>readFileSync(new URL('../'+name,import.meta.url),'utf8');
const app=read('index.html'),cloud=read('cloud-sync.js'),
  vault=read('device-vault.js'),worker=read('sw.js'),rules=read('firestore.rules');
const localKey='masareefi_v2_review_20261028_isolated';

test('JavaScript sources and all inline scripts parse',()=>{
 for(const [name,source] of [['cloud',cloud],['vault',vault],['worker',worker]])
  assert.doesNotThrow(()=>new vm.Script(source,{filename:name}));
 for(const match of app.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi))
  assert.doesNotThrow(()=>new vm.Script(match[1]));
});
test('RC23 uses original financial key and isolated user-specific Firestore',()=>{
 assert.ok(app.includes("const KEY='"+localKey+"'"));
 assert.match(cloud,/masareefi_finance_sync_v19/);
 assert.match(rules,/request\.auth\.uid == userId/);
 assert.match(rules,/allow list, delete: if false;/);
});
test('manual backup contains attachments while cloud omits them',()=>{
 assert.match(app,/async function backupWithFiles\(\)/);
 assert.match(app,/_receiptBackup:\{format:1,attachments\}/);
 assert.match(cloud,/k!=='_receiptBackup'/);
});
test('all three restore flows explicitly pause cloud sync',()=>{
 assert.equal((app.match(/onBulkRestore/g)||[]).length,3);
 assert.match(cloud,/function onBulkRestore\(\)/);
 assert.match(cloud,/setRestoreHold\(\)/);
 assert.match(cloud,/if\(hasRestoreHold\(\)&&!choice\)/);
});
test('cloud writes use atomic manifest condition and stale-data guard',()=>{
 assert.match(cloud,/existing\?\{updateTime:existing\.updateTime\}:\{exists:false\}/);
 assert.match(cloud,/if\(\(await currentHash\(\)\)!==hash\)throw Error/);
 assert.match(cloud,/if\(\(await currentHash\(\)\)!==originalHash\)/);
});
test('automatic reconnect is opt-in; the vault does not persist plaintext passwords',()=>{
 assert.match(vault,/async function rememberAutomatic\(secrets\)/);
 assert.match(vault,/generateKey\(\{name:'AES-GCM',length:256\},false/);
 assert.ok(!vault.includes('localStorage'));
 assert.match(cloud,/syncAutoV22/);
});
test('PWA caches and refreshes both sync scripts',()=>{
 assert.match(worker,/'\.\/device-vault\.js','\.\/cloud-sync\.js'/);
 assert.match(app,/cloud-sync\.js\?v=23/);
});
test('classification blocks concurrent changes rather than selecting a winner',()=>{
 const source=cloud.match(/function classification\(remoteHash,localHash,baselineHash\)\{[\s\S]*?\n\}/)?.[0];
 assert.ok(source,'classification source missing');
 const classify=new Function(source+'; return classification')();
 assert.equal(classify('r','r','base'),'equal');
 assert.equal(classify(null,'l',null),'empty');
 assert.equal(classify('base','changed','base'),'upload');
 assert.equal(classify('changed','base','base'),'download');
 assert.equal(classify('cloud','local','base'),'conflict');
});
function client(localStorage){
 const window={addEventListener(){}};
 const document={getElementById(id){
  return id==='financeSyncSettingsV19'?{addEventListener(){}}:null;
 },addEventListener(){},querySelector(){return null},visibilityState:'visible'};
 const nav={onLine:true},fetch=async(url)=>{
  if(String(url).includes('signInWithPassword'))return {ok:true,status:200,json:async()=>({
   localId:'unit_test_user_12345',idToken:'unit-test-token',
   refreshToken:'unit-test-refresh-token-1234567890',expiresIn:3600
  })};
  if(String(url).includes('/sync/meta'))return {ok:false,status:404,json:async()=>({error:{status:'NOT_FOUND'}})};
  throw Error('Unexpected mock URL: '+String(url));
 };
 const inject="window.masareefiSyncV19={onPersist,onBulkRestore,openSettings,synchronize,stableStringify,classification,disconnect};";
 assert.ok(cloud.includes(inject));
 const script=cloud.replace(inject,inject+"window.__rcAudit={signIn,onBulkRestore,getState:()=>session,getNotice:()=>session.notice};");
 vm.runInNewContext(script,{
  window,document,localStorage,navigator:nav,fetch,crypto:webcrypto,
  TextEncoder,TextDecoder,URL,URLSearchParams,AbortController,
  btoa:binary=>Buffer.from(binary,'binary').toString('base64'),
  atob:encoded=>Buffer.from(encoded,'base64').toString('binary'),
  setTimeout(){return 1},clearTimeout(){},setInterval(){},
  data:{transactions:[],savings:[],receivables:[],goals:[],debts:[],budgets:{}},
  openModal(){},safe:String,hydrate:x=>x,render(){},KEY:'isolated_mock_financial_data',
 });
 return window.__rcAudit;
}
test('a restored backup stays quarantined after page reload and login',async()=>{
 const map=new Map();
 const store={getItem:k=>map.get(k)||null,setItem:(k,v)=>map.set(k,String(v)),
  removeItem:k=>map.delete(k)};
 let first=client(store);
 await first.signIn('masareefi-finance-33a25','FAKE_PUBLIC_WEB_KEY_123456',
  'person@example.test','test-password','long-test-encryption-phrase');
 first.onBulkRestore();
 assert.equal(map.get('masareefi_finance_sync_v23_restore_hold'),'1');
 const second=client(store);
 await second.signIn('masareefi-finance-33a25','FAKE_PUBLIC_WEB_KEY_123456',
  'person@example.test','test-password','long-test-encryption-phrase');
 assert.equal(second.getState().active,false);
 assert.match(second.getNotice(),/المزامنة التلقائية معلّقة/);
});
