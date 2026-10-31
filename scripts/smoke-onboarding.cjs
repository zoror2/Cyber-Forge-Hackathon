// Optional browser test only. The Go application serves no JavaScript.
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
const base = 'http://127.0.0.1:8080';
if (!key || key.length < 32) throw new Error('A private local tenant API key is required.');

async function localContext(browser, viewport) {
  const context = await browser.newContext({
    httpCredentials: {username: 'apikey', password: key, origin: base},
    viewport, acceptDownloads: true,
  });
  await context.route('**/*', route => {
    if (new URL(route.request().url()).origin === base) return route.continue();
    return route.abort();
  });
  return context;
}

(async () => {
  fs.mkdirSync('data', {recursive: true});
  const browser = await chromium.launch({
    executablePath: process.env.CB_TEST_EDGE_PATH ||
      'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
    args: ['--no-first-run', '--disable-background-networking'],
  });
  try {
    const context = await localContext(browser, {width: 1440, height: 1050});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', () => errors.push('page_error'));
    await page.goto(base + '/onboarding');
    await page.getByRole('heading', {name: /Bring another source/}).waitFor();
    assert(!(await page.content()).includes(key));
    await page.screenshot({path: 'data/b5-form-desktop.png'});

    const id = 'browser_users_' + Date.now();
    await page.locator('[name=id]').fill(id);
    await page.locator('[name=name]').fill('Local vendor users');
    await page.locator('[name=url]').fill('https://127.0.0.1:8081/users');
    await page.locator('[name=port]').fill('8081');
    await page.locator('[name=pagination_type]').selectOption('page');
    await page.getByText('Pagination fields & query parameters', {exact: true}).click();
    await page.locator('[name=page_size]').fill('10');
    await page.locator('[name=path_name]').fill('profile.name');
    await page.locator('[name=notifications_enabled]').check();

    await page.getByRole('button', {name: 'Generate config'}).click();
    await page.locator('#generated-config').waitFor();
    const config = JSON.parse(await page.locator('#generated-config').innerText());
    assert.equal(config.id, id);
    assert.equal(config.notifications.failure_threshold, 3);
    assert.equal(config.schedule.enabled, false);
    assert(!JSON.stringify(config).includes(key));

    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', {name: 'Download JSON'}).click();
    const download = await downloadPromise;
    await download.saveAs(path.resolve('data/b5-browser-config.json'));
    assert.equal(JSON.parse(fs.readFileSync('data/b5-browser-config.json', 'utf8')).id, id);

    await page.getByRole('button', {name: 'Save as draft'}).click();
    await page.getByText('Saved as a draft. No automatic collection has started.', {exact: true}).waitFor();
    await page.getByRole('button', {name: 'Test saved draft'}).click();
    await page.getByRole('heading', {name: 'Connection test: success'}).waitFor();
    assert.equal(await page.locator('#test-result .metrics b').nth(1).innerText(), '10');
    await page.screenshot({path: 'data/b5-draft-tested.png', fullPage: true});

    const headers = {Authorization: 'Bearer ' + key};
    for (const route of ['/records/users?source=', '/runs?connector=', '/alerts?connector=']) {
      const result = await fetch(base + route + id, {headers});
      assert.equal(result.status, 200);
      assert.deepEqual(await result.json(), []);
    }
    const attempt = await fetch(base + '/connectors/' + id + '/run', {method: 'POST', headers});
    assert.equal(attempt.status, 404);

    const mobile = await localContext(browser, {width: 390, height: 844});
    const mobilePage = await mobile.newPage();
    await mobilePage.goto(base + '/onboarding');
    assert(await mobilePage.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await mobilePage.screenshot({path: 'data/b5-form-mobile.png'});
    assert.equal(errors.length, 0);
    fs.writeFileSync('data/b5-browser-result.json', JSON.stringify({
      passed: true, connector: id, generated: true, downloaded: true, saved_draft: true,
      preview_accepted: 10, no_records_written: true, no_runs_written: true,
      no_alerts_written: true, still_inactive: true, mobile_no_overflow: true,
    }, null, 2));
    console.log('PASS: Edge generated/downloaded/saved/tested a draft; 10 accepted; no production writes or activation; mobile fits.');
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(('Browser flow failed: ' + String(error.message || error))
    .split(key).join('[redacted]').slice(0, 1200));
  process.exitCode = 1;
});
