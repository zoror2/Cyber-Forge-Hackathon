'use strict';
const fs=require('fs');const assert=require('assert/strict');
let chromium;try{({chromium}=require('playwright-core'));}catch{({chromium}=require('../.tools/ui-check/node_modules/playwright-core'));}
(async()=>{
 const browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});const page=await browser.newPage();page.setDefaultTimeout(20000);const errors=[];page.on('pageerror',e=>errors.push(e.message));const base='http://127.0.0.1:55080';
 try{
  await page.goto(base+'/ui/');await page.getByLabel('Account',{exact:true}).fill('jury-demo');await page.getByLabel('Email',{exact:true}).fill('jury@demo.test');await page.getByLabel('Password',{exact:true}).fill('Jury-demo-only-2026!');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByRole('heading',{name:'Overview',exact:true}).waitFor();
  const usage=()=>page.evaluate(async()=>{const r=await fetch('/ai/usage');if(!r.ok)throw Error('usage unavailable');return(await r.json()).requests});const before=await usage();
  const yaml=fs.readFileSync('configs/mock_users.yaml','utf8');
  for(const format of ['paste_yaml','upload_yaml','upload_json']){
   const id='format_'+format;await page.goto(base+'/ui/#/builder');await page.getByRole('button',{name:'Paste a config',exact:true}).click();
   const text=format==='upload_json'?JSON.stringify({...JSON.parse(fs.readFileSync('configs/mock_users.json','utf8')),id}):yaml.replace('id: mock_users','id: '+id);
   if(format==='paste_yaml')await page.getByLabel('Config JSON or YAML',{exact:true}).fill(text);
   else await page.getByLabel('Upload config file',{exact:true}).setInputFiles({name:format==='upload_yaml'?'connector.yml':'connector.json',mimeType:format==='upload_yaml'?'application/yaml':'application/json',buffer:Buffer.from(text)});
   await page.getByLabel('Config JSON or YAML',{exact:true}).waitFor();await page.getByRole('button',{name:'Check config',exact:true}).click();await page.getByRole('button',{name:'Connect',exact:true}).waitFor();
   if(format==='paste_yaml'){
    await page.getByLabel('Config JSON or YAML',{exact:true}).fill(text+'\n# edited after checking');assert.equal(await page.getByRole('button',{name:'Connect',exact:true}).count(),0);await page.getByRole('button',{name:'Check config',exact:true}).click();await page.getByRole('button',{name:'Connect',exact:true}).waitFor();
   }
   await page.getByRole('button',{name:'Connect',exact:true}).click();await page.getByRole('link',{name:'See the data',exact:true}).waitFor({timeout:30000});await page.getByRole('link',{name:'See the data',exact:true}).click();await page.getByText('User 01',{exact:true}).waitFor();console.log('PASS: '+format+' → normalize → preview → activate → collect → OCSF records.');
  }
  await page.goto(base+'/ui/#/builder');await page.getByRole('button',{name:'Paste a config',exact:true}).click();await page.getByLabel('Config JSON or YAML',{exact:true}).fill('version: 1\nversion: 2');await page.getByRole('button',{name:'Check config',exact:true}).click();await page.getByText(/invalid YAML:/).waitFor();assert.equal(await page.getByRole('button',{name:'Connect',exact:true}).count(),0);assert.equal(await usage(),before);assert.deepEqual(errors,[]);console.log('PASS: duplicate-key refusal, stale-review invalidation, zero AI calls and no JavaScript errors.');await page.screenshot({path:'data/config-formats.png',fullPage:true});
 }finally{await browser.close();}
})().catch(e=>{console.error(e.message);process.exitCode=1});
