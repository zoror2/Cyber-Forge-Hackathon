'use strict';
const fs=require('fs');const assert=require('assert/strict');
let chromium;try{({chromium}=require('playwright-core'));}catch{({chromium}=require('../.tools/ui-check/node_modules/playwright-core'));}
const base='http://127.0.0.1:55080';
const settings=Object.fromEntries(fs.readFileSync('data/docker-app-proof/settings.env','utf8').split(/\r?\n/).filter(x=>x.includes('=')).map(x=>[x.slice(0,x.indexOf('=')),x.slice(x.indexOf('=')+1)]));
(async()=>{
 const browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage({viewport:{width:1440,height:1100}});page.setDefaultTimeout(20000);const errors=[],checks=[];page.on('pageerror',e=>errors.push(e.message));
 const check=async(name,fn)=>{if(process.argv.includes('--draft-only')&&!name.startsWith('Reviewed AI'))return;try{await fn();checks.push({name,status:'passed'});console.log('PASS: '+name);}catch(e){checks.push({name,status:'failed',detail:e.message});console.error('FAIL: '+name+' '+e.message);}};
 const login=async(account)=>{await page.goto(base+'/ui/');await page.getByLabel('Account',{exact:true}).fill(account);await page.getByLabel('Email',{exact:true}).fill('jury@demo.test');await page.getByLabel('Password',{exact:true}).fill('Jury-demo-only-2026!');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByRole('heading',{name:'Overview',exact:true}).waitFor();};
 try{
  await login('jury-demo');
  await check('Reviewed AI config template, official sources and required local inputs',async()=>{
   await page.goto(base+'/ui/#/builder');await page.getByLabel('Product',{exact:true}).fill('GitHub');await page.getByLabel('Dataset / scope',{exact:true}).selectOption('github_public_contributors');await page.getByRole('button',{name:'Set it up',exact:true}).click();await page.getByLabel('Repository owner',{exact:true}).waitFor({timeout:110000});assert(await page.getByRole('button',{name:'Connect',exact:true}).isDisabled());
   await page.getByLabel('Repository owner',{exact:true}).fill('octocat');await page.getByLabel('Public repository name',{exact:true}).fill('Hello-World');await page.getByRole('button',{name:'Apply dataset inputs',exact:true}).click();assert((await page.locator('main').innerText()).includes('https://api.github.com/repos/octocat/Hello-World/contributors'));assert(await page.locator('a[href*="docs.github.com/en/rest/repos/repos"]').count());await page.screenshot({path:'data/jury-ai-draft.png',fullPage:true});
  });
  await check('Overview, sources, records, runs, secrets and IAM pages',async()=>{
   for(const [route,title]of [['connectors','Sources'],['records?class=user_inventory&source=demo_users','OCSF records'],['runs','Runs'],['secrets','Secrets'],['access','Users & keys']]){await page.goto(base+'/ui/#/'+route);await page.getByRole('heading',{name:title,exact:true}).waitFor();}
   await page.goto(base+'/ui/#/records?class=user_inventory&source=demo_users');await page.getByText('User 01',{exact:true}).waitFor();
  });
  await check('KEV dashboard shows exactly the two matching synthetic assets',async()=>{await page.goto(base+'/ui/#/kev-alerts');await page.getByRole('heading',{name:'KEV alerts',exact:true}).waitFor();await page.getByText('CVE-2021-44228',{exact:true}).waitFor();await page.getByText('CVE-2024-3400',{exact:true}).waitFor();assert(!(await page.locator('main').innerText()).includes('CVE-2099-99999'));await page.screenshot({path:'data/jury-kev.png',fullPage:true});});
  await check('Free-text question, consent, sensitive-input refusal and real AI answer',async()=>{
   await page.goto(base+'/ui/#/insights?connector=demo_vulnerabilities&topic=security_findings');await page.getByLabel('Your question').fill('What does the KEV match mean and what should I verify?');await page.getByRole('button',{name:'Explain',exact:true}).click();await page.getByText('Tick the consent box first.',{exact:true}).waitFor();
   await page.getByRole('checkbox').check();await page.getByLabel('Your question').fill('api_key=synthetic-private-input');await page.getByRole('button',{name:'Explain',exact:true}).click();await page.getByText('invalid siem question',{exact:true}).waitFor();
   await page.getByLabel('Your question').fill('What does the KEV match mean and what should I verify?');await page.getByRole('button',{name:'Explain',exact:true}).click();await page.getByRole('heading',{name:'AI explanation',exact:true}).waitFor({timeout:110000});await page.screenshot({path:'data/jury-question.png',fullPage:true});
  });
  await check('Customer usage and protected platform dashboard',async()=>{
   await page.goto(base+'/ui/#/ai-usage');await page.locator('[data-testid="ai-totals"]').waitFor();assert.equal(await page.evaluate(async()=>{const r=await fetch('/operator/ai/consumption');return r.status}),401);
   await page.goto(base+'/ui/#/platform-ai');await page.getByLabel('Platform operator credential').fill(settings.CB_OPERATOR_TOKEN);await page.getByRole('button',{name:'Open platform usage',exact:true}).click();await page.getByRole('heading',{name:'Consumption by customer',exact:true}).waitFor();assert(await page.getByRole('button',{name:'jury-demo',exact:true}).count());
   const storage=await page.evaluate(()=>JSON.stringify([localStorage,sessionStorage,document.cookie,location.href]));assert(!storage.includes(settings.CB_OPERATOR_TOKEN));await page.getByRole('button',{name:'Lock platform view',exact:true}).click();await page.getByLabel('Platform operator credential').waitFor();
  });
  await check('AI repair previews, activates and reruns from Quarantine',async()=>{
   await page.goto(base+'/ui/#/quarantine?connector=demo_repair');await page.getByRole('heading',{name:'Quarantine',exact:true}).waitFor();await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Fix config with AI',exact:true}).first().click();await page.getByText('repaired and rerun',{exact:true}).waitFor({timeout:110000});assert((await page.getByRole('status').innerText()).includes('25 accepted, 0 quarantined'));await page.screenshot({path:'data/jury-repair.png',fullPage:true});
  });
  await check('Manual config wizard checks, previews, activates and collects',async()=>{
   const c=JSON.parse(fs.readFileSync('configs/mock_users.json','utf8'));c.id='demo_browser';c.name='SYNTHETIC browser source';
   await page.goto(base+'/ui/#/builder');await page.getByRole('button',{name:'Paste a config',exact:true}).click();await page.getByLabel('Config JSON',{exact:true}).fill(JSON.stringify(c));await page.getByRole('button',{name:'Check config',exact:true}).click();await page.getByRole('button',{name:'Connect',exact:true}).click();await page.getByRole('link',{name:'See the data',exact:true}).waitFor({timeout:30000});await page.getByRole('link',{name:'See the data',exact:true}).click();await page.getByText('User 01',{exact:true}).waitFor();
  });
  await check('Second customer cannot see KEV alerts or first customer records',async()=>{
   await page.getByRole('button',{name:'Sign out',exact:true}).click();await login('jury-other');await page.goto(base+'/ui/#/kev-alerts');await page.getByText(/CISA catalog missing/).waitFor();assert(!(await page.locator('main').innerText()).includes('CVE-2021-44228'));await page.goto(base+'/ui/#/connectors');await page.getByRole('heading',{name:'Sources',exact:true}).waitFor();assert(!(await page.locator('main').innerText()).includes('demo_users'));
  });
  assert.deepEqual(errors,[]);console.log('PASS: no browser JavaScript errors.');
 }finally{fs.writeFileSync(process.argv.includes('--draft-only')?'data/jury-draft-browser-checks.json':'data/jury-browser-checks.json',JSON.stringify({checks,errors,checked_at:new Date().toISOString()},null,2));await browser.close();}
 if(checks.some(c=>c.status==='failed'))process.exitCode=1;
})().catch(e=>{console.error(e.message);process.exitCode=1});
