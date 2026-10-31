// Browser verification only; the Go application serves no JavaScript.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {chromium} = require(path.resolve('.tools/ui-check/node_modules/playwright-core'));
const settings = {};
for (const line of fs.readFileSync('.env', 'utf8').split(/\r?\n/)) {
  const at = line.indexOf('=');
  if (at > 0) settings[line.slice(0, at)] = line.slice(at + 1);
}
const key = settings.CB_BOOTSTRAP_API_KEY;
if (!key) throw new Error('Private local API key required.');
const base = 'http://127.0.0.1:18080';
const demo = JSON.parse(fs.readFileSync('data/siem-demo-result.json', 'utf8'));
async function context(browser, viewport) {
  const result = await browser.newContext({viewport,
    httpCredentials: {username: 'apikey', password: key, origin: base}});
  await result.route('**/*', route => new URL(route.request().url()).origin === base
    ? route.continue() : route.abort());
  return result;
}
(async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CB_TEST_EDGE_PATH || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true, args: ['--no-first-run', '--disable-background-networking'],
  });
  try {
    const desktop = await context(browser, {width: 1440, height: 1050});
    const page = await desktop.newPage();
    await page.goto(base + '/insights?connector=' + demo.connector);
    await page.getByRole('heading', {name: 'AI consumption'}).waitFor();
    assert(!(await page.content()).includes(key));
    await page.getByRole('button', {name: 'Refresh findings', exact: true}).click();
    await page.locator('#siem-findings').waitFor();
    assert((await page.locator('#siem-findings').innerText()).includes('authentication_failures'));
    await page.locator('[name=topic]').selectOption('security_findings');
    // Missing consent must fail locally before a provider call.
    await page.getByRole('button', {name: 'Explain selected evidence'}).click();
    await page.getByRole('alert').waitFor();
    assert((await page.getByRole('alert').innerText()).includes('consent'));
    await page.locator('[name=consent]').check();
    // One real provider request, using the synthetic demo's aggregate facts only.
    await page.getByRole('button', {name: 'Explain selected evidence'}).click();
    await page.locator('#siem-answer').waitFor();
    const text = await page.locator('#siem-answer').innerText();
    assert(text.includes('Supporting evidence'));
    for (const privateValue of [key, 'SYNTHETIC_PRIVATE_DESCRIPTION', 'user@example.invalid', '192.0.2.1']) {
      assert(!text.includes(privateValue));
    }
    assert(Number(await page.locator('#ai-usage b').nth(3).innerText()) > 0);
    await page.screenshot({path: 'data/siem-dashboard-desktop.png', fullPage: true});
    const mobile = await context(browser, {width: 390, height: 844});
    const phone = await mobile.newPage();
    await phone.goto(base + '/insights?connector=' + demo.connector);
    assert(await phone.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await phone.screenshot({path: 'data/siem-dashboard-mobile.png', fullPage: true});
    fs.writeFileSync('data/siem-browser-result.json', JSON.stringify({
      passed: true, refreshed: true, consent_enforced: true, synthetic_ai_explanation: true,
      supporting_evidence: true, token_usage_visible: true, mobile_no_overflow: true,
    }, null, 2));
    console.log('PASS: Edge refreshed findings, enforced consent, showed a real Groq explanation/evidence/token usage; mobile fits.');
  } finally { await browser.close(); }
})().catch(error => {
  console.error(('Browser check failed: ' + String(error.message || error)).split(key).join('[redacted]').slice(0, 1000));
  process.exitCode = 1;
});
