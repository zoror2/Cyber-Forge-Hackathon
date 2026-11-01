'use strict';
// Local Docker demo only: requires the synthetic mailbox and jury demo accounts.
// Never use this harness with real SMTP: it deliberately exercises failure alerts.
const fs = require('fs'), assert = require('assert/strict');
const { execFileSync } = require('child_process');
let chromium;
try { ({ chromium } = require('playwright-core')); }
catch { ({ chromium } = require('../.tools/ui-check/node_modules/playwright-core')); }
const base = 'http://127.0.0.1:55080';
const docker = process.env.DOCKER_EXE || 'C:/Users/Admin/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe';
(async () => {
  const browser = await chromium.launch({ executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 1500, height: 1000 } });
  const errors = []; page.on('pageerror', e => errors.push(e.message)); page.setDefaultTimeout(20000);
  const id = 'b4_browser_' + Date.now();
  const call = async (method, path, body, expected = 200) => page.evaluate(async ({ method, path, body, expected }) => {
    const r = await fetch(path, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    const d = await r.json(); if (r.status !== expected) throw Error(path + ': HTTP ' + r.status); return d;
  }, { method, path, body, expected });
  const login = async account => {
    await page.goto(base + '/ui/');
    await page.getByLabel('Account', { exact: true }).fill(account);
    await page.getByLabel('Email', { exact: true }).fill('jury@demo.test');
    await page.getByLabel('Password', { exact: true }).fill('Jury-demo-only-2026!');
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.getByRole('heading', { name: 'Overview', exact: true }).waitFor();
  };
  try {
    await login('jury-demo');
    const status = await call('GET', '/notifications/status');
    assert.equal(status.delivery_mode, 'local_capture', 'Refusing to test against external SMTP');
    const c = JSON.parse(fs.readFileSync('configs/mock_users.json', 'utf8'));
    Object.assign(c, { id, name: 'SYNTHETIC B-4 browser verification', pagination: { type: 'none' }, notifications: { enabled: false, failure_threshold: 3, cooldown_seconds: 3600 } });
    c.request.url = 'https://mockvendor:8081/flaky'; c.request.params = { scenario_id: id, fail: '100', code: '500' }; c.retry.max_attempts = 1;
    const saved = await call('POST', '/configs', c, 201);
    await call('POST', '/configs/' + id + '/activate', { revision: saved.revision });
    await page.goto(base + '/ui/#/email-alerts');
    await page.getByRole('heading', { name: 'Local test mailbox configured', exact: true }).waitFor();
    await page.getByRole('row').filter({ hasText: id }).getByRole('link', { name: 'Edit source', exact: true }).click();
    await page.getByRole('checkbox', { name: 'Email after repeated failures', exact: true }).check();
    await page.getByLabel('Consecutive failures', { exact: true }).fill('3');
    await page.getByLabel('Cooldown (seconds)', { exact: true }).fill('3600');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await page.getByText(/rev 2 saved as draft/).waitFor();
    assert.equal((await call('GET', '/configs?limit=500')).find(x => x.id === id).live_notifications.enabled, false);
    await page.getByRole('button', { name: 'Activate', exact: true }).click();
    await page.getByText('rev 2 is live', { exact: true }).waitFor();
    assert.equal((await call('GET', '/configs?limit=500')).find(x => x.id === id).live_notifications.enabled, true);
    console.log('PASS: dashboard edits notification settings; draft does not change live settings until activation.');
    await call('POST', '/connectors/' + id + '/test', undefined, 502);
    for (let i = 0; i < 2; i++) await call('POST', '/connectors/' + id + '/run', undefined, 502);
    assert.deepEqual(await call('GET', '/alerts?connector=' + id), []);
    await call('POST', '/connectors/' + id + '/run', undefined, 502);
    await page.goto(base + '/ui/#/email-alerts?connector=' + id);
    await page.getByRole('heading', { name: 'Delivery history', exact: true }).waitFor();
    let delivered = false;
    for (let i = 0; i < 40; i++) {
      const outbox = await call('GET', '/alerts?connector=' + id);
      if (outbox.length === 1 && outbox[0].status === 'sent') { delivered = true; break; }
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    assert(delivered, 'Local worker did not deliver the alert');
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await page.getByRole('heading', { name: 'Delivery history', exact: true }).waitFor();
    await page.getByText('sent', { exact: true }).waitFor();
    await call('POST', '/connectors/' + id + '/run', undefined, 502);
    // Capture binds only to loopback inside the API network namespace.
    const rawMessages = execFileSync(docker, ['run', '--rm', '--network', 'container:cb-app-proof-api-1', '--entrypoint', 'curl', 'cb-app-proof-go-check', '-fsS', 'http://127.0.0.1:8025/messages'], { encoding: 'utf8', timeout: 30000 });
    const messages = JSON.parse(rawMessages).filter(x => x.body.includes('Connector: ' + id));
    assert.equal(messages.length, 1); assert(messages[0].body.includes('Consecutive failed collections: 3'));
    await page.screenshot({ path: 'data/email-alerts-browser.png', fullPage: true });
    console.log('PASS: preview ignored; third live failure sends one captured email; fourth failure does not duplicate.');
    const current = (await call('GET', '/configs/' + id)).config;
    current.request.url = 'https://mockvendor:8081/users'; current.request.params = { per_page: '100' };
    let next = await call('POST', '/configs', current, 201);
    await call('POST', '/configs/' + id + '/activate', { revision: next.revision });
    assert.equal((await call('POST', '/connectors/' + id + '/run')).outcome, 'success');
    current.notifications.enabled = false;
    next = await call('POST', '/configs', current, 201); await call('POST', '/configs/' + id + '/activate', { revision: next.revision });
    await page.getByRole('button', { name: 'Sign out', exact: true }).click(); await login('jury-other');
    await page.goto(base + '/ui/#/email-alerts'); await page.getByRole('heading', { name: 'Email delivery is not configured', exact: true }).waitFor();
    assert(!(await page.locator('main').innerText()).includes(id));
    await call('GET', '/alerts?connector=' + id, undefined, 404);
    assert.deepEqual(errors, []);
    fs.writeFileSync('data/email-browser-result.json', JSON.stringify({ connector: id, captured: 1, isolation: true, recovered: true, external_email_sent: false, errors, checked_at: new Date().toISOString() }, null, 2));
    console.log('PASS: recovery, opt-out, second-customer isolation and no JavaScript errors.');
  } catch (e) {
    console.error('Browser errors: ' + JSON.stringify(errors));
    console.error((await page.locator('main').innerText().catch(() => '')).slice(-1300));
    await page.screenshot({ path: 'data/email-browser-failure.png', fullPage: true }).catch(() => {});
    throw e;
  } finally { await browser.close(); }
})().catch(e => { console.error(e.message); process.exitCode = 1; });
