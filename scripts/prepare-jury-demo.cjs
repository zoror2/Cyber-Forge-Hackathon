'use strict';
// Explicit local demo only. Uses the existing Docker setup; creates synthetic
// accounts/sources, never deletes data or sends external notification emails.
const fs = require('fs');
const assert = require('assert/strict');
const https = require('https');
const base = process.env.CB_DEMO_URL || 'http://127.0.0.1:55080';
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(base)) throw new Error('Demo preparation is restricted to IPv4 loopback.');
const settingsPath = process.env.CB_DEMO_SETTINGS || 'data/docker-app-proof/settings.env';
const settings = Object.fromEntries(fs.readFileSync(settingsPath, 'utf8').split(/\r?\n/).filter(x => /^[A-Z0-9_]+=/.test(x)).map(x => [x.slice(0,x.indexOf('=')),x.slice(x.indexOf('=')+1)]));
const password = 'Jury-demo-only-2026!';
const report = { checked_at: new Date().toISOString(), checks: [], base, synthetic: true };
const read = file => JSON.parse(fs.readFileSync(file,'utf8'));
const clone = x => structuredClone(x);
async function call(path, method='GET', body, cookie, expected=200) {
  const headers = {'Content-Type':'application/json',Origin:base,'Sec-Fetch-Site':'same-origin'};
  if (cookie) headers.Cookie = cookie;
  else if (path === '/accounts') headers.Authorization = 'Bearer ' + settings.CB_OPERATOR_TOKEN;
  const r = await fetch(base+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(90000)});
  const text = await r.text(); let data; try { data=JSON.parse(text); } catch { data=text; }
  if (!(Array.isArray(expected)?expected:[expected]).includes(r.status)) throw new Error(path+' HTTP '+r.status+' '+JSON.stringify(data));
  return {data,cookie:r.headers.getSetCookie().map(x=>x.split(';')[0]).join('; ')};
}
async function account(id) {
  await call('/accounts','POST',{account:id,name:'Synthetic jury demo',email:'jury@demo.test',password},null,[201,409]);
  return (await call('/auth/login','POST',{account:id,email:'jury@demo.test',password})).cookie;
}
async function source(cookie,c) {
  const s=(await call('/configs','POST',c,cookie,[200,201])).data;
  await call('/configs/'+c.id+'/activate','POST',{revision:s.revision},cookie);
  fs.mkdirSync('data/jury-demo-configs',{recursive:true});
  fs.writeFileSync('data/jury-demo-configs/'+c.id+'.json',JSON.stringify(c,null,2));
  return s;
}
async function run(cookie,id,status=200){return (await call('/connectors/'+id+'/run','POST',undefined,cookie,status)).data;}
async function check(name,fn){try {const detail=await fn();report.checks.push({name,status:'passed',detail});console.log('PASS: '+name+(detail?' — '+detail:''));}catch(e){report.checks.push({name,status:'failed',detail:e.message});console.error('FAIL: '+name+' — '+e.message);}}
function vendorPost(path){return new Promise((resolve,reject)=>{const r=https.request({hostname:'localhost',family:4,port:55081,path,method:'POST',ca:fs.readFileSync('data/devcert/cert.pem')},res=>{res.resume();res.on('end',()=>res.statusCode<300?resolve():reject(new Error('fixture HTTP '+res.statusCode)))});r.on('error',reject);r.end();});}
async function main(){
 const a=await account('jury-demo'), b=await account('jury-other');
 const users=read('configs/mock_users.json');users.id='demo_users';
 await check('Pagination, mapping, preview and duplicate prevention',async()=>{
  const saved=await source(a,users);
  const before=(await call('/records/user_inventory?source=demo_users','GET',undefined,a)).data.length;
  const p=(await call('/configs/demo_users/test','POST',{revision:saved.revision},a)).data;assert.equal(p.accepted,10);
  assert.equal((await call('/records/user_inventory?source=demo_users','GET',undefined,a)).data.length,before);
  for(let i=0;i<2;i++){const r=await run(a,users.id);assert.equal(r.accepted,25);assert.equal(r.pages,3);assert.equal(r.outcome,'success');}
  assert.equal((await call('/records/user_inventory?source=demo_users','GET',undefined,a)).data.length,25);return '3 pages; 25 unique users after two runs; preview did not store rows';
 });
 await check('Tenant isolation',async()=>{assert.deepEqual((await call('/records/user_inventory','GET',undefined,b)).data,[]);await call('/configs/demo_users','GET',undefined,b,404);return 'second account cannot see the first account’s source or users';});
 await check('Malformed records continue safely',async()=>{const c=clone(users);c.id='demo_malformed';c.name='SYNTHETIC mixed valid/invalid users';c.request.url='https://mockvendor:8081/malformed';c.pagination={type:'none'};await source(a,c);const r=await run(a,c.id);assert.equal(r.accepted,2);assert.equal(r.quarantined,2);return '2 accepted, 2 quarantined';});
 await check('Prepare deliberate conversion error for AI repair',async()=>{const c=clone(users);c.id='demo_repair';c.name='SYNTHETIC repair exercise';c.destination.mapping['user.name'].transform='integer';await source(a,c);const r=await run(a,c.id);assert.equal(r.quarantined,25);return '25 rejected rows; use Quarantine → Fix config with AI';});
 await check('Security findings and actual OpenSearch indexing',async()=>{const c=read('configs/mock_security_events.json');c.id='demo_security';c.request.url='https://mockvendor:8081/security-events';await source(a,c);assert.equal((await run(a,c.id)).accepted,9);const snap=(await call('/siem/refresh','POST',{connector:c.id},a)).data;assert(snap.findings.some(f=>f.rule==='authentication_failures'&&f.count===6));assert(snap.findings.some(f=>f.rule==='high_severity_events'&&f.count===1));return '9 synthetic events; 6 failed logins and 1 recent high-severity event';});
 await check('Real CISA feed plus synthetic asset CVE matching',async()=>{
  const c=read('configs/cisa_kev.json');c.request.url='https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json';await source(a,c);const collected=await run(a,c.id);assert.equal(collected.outcome,'success');assert(collected.accepted>100);
  const v=read('configs/mock_vulnerabilities.json');v.id='demo_vulnerabilities';v.request.url='https://mockvendor:8081/vulnerabilities';await source(a,v);assert.equal((await run(a,v.id)).accepted,3);
  const matches=(await call('/kev/matches','GET',undefined,a)).data;assert.equal(matches.total,2);assert(matches.matches.some(m=>m.cve==='CVE-2021-44228'));assert(matches.matches.some(m=>m.cve==='CVE-2024-3400'));
  assert.equal((await call('/kev/matches','GET',undefined,b)).data.status,'catalog_missing');return collected.accepted+' real catalog entries; exactly 2 synthetic asset matches';
 });
 await check('Encrypted host-bound vendor credential',async()=>{await call('/secrets/demo_vendor_token_port','PUT',{value:'mock-token',allowed_host:'mockvendor:8081'},a,204);const c=clone(users);c.id='demo_secure';c.name='SYNTHETIC bearer authentication';c.request.url='https://mockvendor:8081/secure';c.auth={type:'bearer',secret:'demo_vendor_token_port'};c.pagination={type:'none'};await source(a,c);assert.equal((await run(a,c.id)).outcome,'success');const metadata=JSON.stringify((await call('/secrets','GET',undefined,a)).data);assert(!metadata.includes('mock-token'));return 'bearer request succeeds; API lists metadata without secret values';});
 await check('Retry and Retry-After',async()=>{for(const [id,path,query,attempts] of [['demo_retry','flaky',{scenario_id:String(Date.now()),fail:'2',code:'500'},3],['demo_rate_limit','ratelimit',{scenario_id:String(Date.now()),retry_after:'1'},2]]){const c=clone(users);c.id=id;c.name='SYNTHETIC '+id;c.request.url='https://mockvendor:8081/'+path;c.request.params=query;c.pagination={type:'none'};c.retry.base_delay_ms=100;await source(a,c);const r=await run(a,id);assert.equal(r.outcome,'success');assert.equal(r.attempts,attempts);}return '5xx recovered after 3 attempts; 429 recovered after 2';});
 await check('Timeout, redirect refusal and response limit',async()=>{for(const [id,path,query,error]of [['demo_timeout','hang',{seconds:'3'},'timeout'],['demo_redirect','redirect',{},'destination_denied'],['demo_size','huge',{mb:'2'},'response_too_large']]){const c=clone(users);c.id=id;c.name='SYNTHETIC expected failure: '+id;c.request.url='https://mockvendor:8081/'+path;c.request.params=query;c.request.timeout_seconds=1;c.pagination={type:'none'};c.retry.max_attempts=1;if(id==='demo_size')c.limits.max_response_bytes=1024;await source(a,c);const r=await run(a,id,502);assert.equal(r.error,error);}return 'all three failed safely with explicit reasons';});
 await check('Incremental changes and checkpoint',async()=>{await vendorPost('/incremental/reset');const c=read('configs/mock_incremental_users.json');c.id='demo_incremental_'+Date.now();await source(a,c);const first=await run(a,c.id);assert.equal(first.accepted,3);assert.equal((await run(a,c.id)).accepted,0);await new Promise(resolve=>setTimeout(resolve,1100));await vendorPost('/incremental/advance');await new Promise(resolve=>setTimeout(resolve,1100));const changed=await run(a,c.id);assert.equal(changed.accepted,2);assert.equal((await call('/records/user_inventory?source='+encodeURIComponent(c.id),'GET',undefined,a)).data.length,4);return c.id+': 3 initial, 0 unchanged, 2 changed; 4 unique users';});
 fs.writeFileSync('data/jury-demo-access.txt','LOCAL SYNTHETIC DEMO ONLY\nURL: '+base+'/ui/\nAccount: jury-demo\nOther account: jury-other\nEmail: jury@demo.test\nPassword: '+password+'\n');
 fs.writeFileSync('data/jury-demo-checks.json',JSON.stringify(report,null,2));
 if(report.checks.some(c=>c.status==='failed'))process.exitCode=1;
}
main().catch(e=>{console.error(e.message);process.exitCode=1;});
