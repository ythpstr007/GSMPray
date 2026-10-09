import test from 'node:test';
import assert from 'node:assert/strict';
import { identity, readJson } from '../shared/security.js';
import { onRequest as middleware } from '../functions/api/_middleware.js';
import { onRequest as dataHandler } from '../functions/api/data.js';
import { onRequest as historyHandler } from '../functions/api/history.js';
const pair = await crypto.subtle.generateKey({ name:'RSASSA-PKCS1-v1_5', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256' }, true, ['sign','verify']);
const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey); jwk.kid='test-key';
const env = { ACCESS_TEAM_DOMAIN:'gsm-security-test.cloudflareaccess.com', ACCESS_AUD:'app-aud', ACCESS_ALLOWED_EMAILS:'leader@example.test, admin@example.test', ACCESS_ADMIN_EMAILS:'admin@example.test' };
const now = Math.floor(Date.now()/1000);
const base = { iss:'https://'+env.ACCESS_TEAM_DOMAIN, aud:['app-aud'], sub:'user-id', email:'leader@example.test', iat:now, exp:now+300 };
const b64 = value => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
async function token(claims=base, header={alg:'RS256',kid:'test-key'}) {
 const payload=b64(header)+'.'+b64(claims);
 const sig=await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,new TextEncoder().encode(payload));
 return payload+'.'+Buffer.from(sig).toString('base64url');
}
const req = (jwt, options={}) => new Request('https://gsm.example.test/api/data',{...options,headers:{'Cf-Access-Jwt-Assertion':jwt,...options.headers}});
const keys = async () => new Response(JSON.stringify({keys:[jwk]}));
test('verified leader identity and server-controlled role',async()=>assert.deepEqual(await identity(req(await token()),env,keys),{email:'leader@example.test',isAdmin:false}));
test('verified administrator',async()=>assert.equal((await identity(req(await token({...base,email:'ADMIN@example.test'})),env,keys)).isAdmin,true));
for(const [name,claims] of [ ['expired',{...base,exp:now-1}],['wrong audience',{...base,aud:['other']}],['wrong issuer',{...base,iss:'https://evil.test'}],['future issued',{...base,iat:now+600}],['not active',{...base,nbf:now+600}],['unapproved email',{...base,email:'stranger@example.test'}],['missing expiry',{...base,exp:undefined}],['missing identity',{...base,sub:undefined}] ]) test('reject '+name,async()=>assert.rejects(()=>token(claims).then(t=>identity(req(t),env,keys))));
test('reject forged signature',async()=>{const t=await token();const p=t.split('.');p[1]=b64({...base,email:'admin@example.test'});await assert.rejects(()=>identity(req(p.join('.')),env,keys));});
test('reject unsigned algorithm',async()=>assert.rejects(()=>token(base,{alg:'none',kid:'test-key'}).then(t=>identity(req(t),env,keys))));
test('fail closed without configuration',async()=>assert.rejects(()=>identity(req('invalid'),{},keys)));
test('missing JWT never reaches protected handler',async()=>{let called=false;const result=await middleware({request:new Request('https://gsm.example.test/api/data'),env,data:{},next:()=>{called=true;}});assert.equal(result.status,401);assert.equal(called,false);});
test('cross-site writes are rejected before storage',async()=>{const result=await middleware({request:new Request('https://gsm.example.test/api/data',{method:'POST',headers:{Origin:'https://evil.test','X-GSM-Request':'1'}}),env,data:{},next:()=>assert.fail()});assert.equal(result.status,403);});
test('same-site POST requires custom header',async()=>{const result=await middleware({request:new Request('https://gsm.example.test/api/data',{method:'POST',headers:{Origin:'https://gsm.example.test'}}),env,data:{},next:()=>assert.fail()});assert.equal(result.status,403);});
test('valid session reaches handler and no cache or wildcard CORS',async()=>{const result=await middleware({request:req(await token()),env,data:{},next:async()=>new Response('[]',{headers:{'Access-Control-Allow-Origin':'*'}})});assert.equal(result.status,200);assert.match(result.headers.get('Cache-Control'),/no-store/);assert.equal(result.headers.get('Access-Control-Allow-Origin'),null);});
function store() {
 const values=new Map([['settings',JSON.stringify({name:'Grace',sub:'Prayer',password:'legacy-secret'})],['people',JSON.stringify([{id:'1',name:'Sample Student',type:'student',prayerRequests:[],updatedAt:1}])]]);
 return {get:async key=>values.get(key),put:async(key,value)=>values.set(key,value),values};
}
function context(path,method='GET',body,user={email:'leader@example.test',isAdmin:false}) {return {request:new Request('https://gsm.example.test'+path,{method,headers:{'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})}),env:{INTERCEDE_KV:store()},data:{user}};}
test('settings never return password',async()=>{const result=await dataHandler(context('/api/data?key=settings'));assert.deepEqual(await result.json(),{name:'Grace',sub:'Prayer'});});
test('setup/reset writes disabled even for admin',async()=>assert.equal((await dataHandler(context('/api/data?key=settings','POST',{password:'attack'},{isAdmin:true}))).status,403));
test('unauthenticated direct handler fails closed',async()=>{const c=context('/api/data');c.data={};assert.equal((await dataHandler(c)).status,401);});
test('leader can save prayer changes',async()=>{const c=context('/api/data','POST',[{id:'1',name:'Sample Student',type:'student',prayerRequests:['Please pray'],updatedAt:2}]);assert.equal((await dataHandler(c)).status,200);assert.deepEqual(JSON.parse(c.env.INTERCEDE_KV.values.get('people'))[0].prayerRequests,['Please pray']);});
test('leader cannot change names',async()=>assert.equal((await dataHandler(context('/api/data','POST',[{id:'1',name:'Changed',type:'student',prayerRequests:[],updatedAt:2}]))).status,403));
test('leader cannot add students',async()=>assert.equal((await dataHandler(context('/api/data','POST',[{id:'2',name:'New',updatedAt:2}]))).status,403));
test('leader cannot force deletion',async()=>assert.equal((await dataHandler(context('/api/data','POST',{force:true,data:[{id:'1',name:'Sample Student'}]}))).status,403));
test('admin can edit roster',async()=>assert.equal((await dataHandler(context('/api/data','POST',[{id:'1',name:'Changed',updatedAt:2}],{isAdmin:true}))).status,200));
test('duplicate ids rejected',async()=>assert.equal((await dataHandler(context('/api/data','POST',[{id:'1',name:'A'},{id:'1',name:'B'}],{isAdmin:true}))).status,400));
test('oversized prayer strings rejected',async()=>assert.equal((await dataHandler(context('/api/data','POST',[{id:'1',name:'A',prayerRequests:['a'.repeat(4001)]}],{isAdmin:true}))).status,400));
test('bounded request reader',async()=>assert.rejects(()=>readJson(new Request('https://gsm.example.test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:'a'.repeat(500)})}),100)));
test('leader cannot rewrite history',async()=>assert.equal((await historyHandler(context('/api/history','POST',[]))).status,403));
test('administrator can save valid history',async()=>assert.equal((await historyHandler(context('/api/history','POST',[{weekStart:now,count:1,total:2}],{isAdmin:true}))).status,200));
