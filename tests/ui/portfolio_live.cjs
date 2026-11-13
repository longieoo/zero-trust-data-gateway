// Real browser integration; synthetic credentials read locally and never emitted.
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../..');
const runtime = path.join(root, '.gateway');
const output = path.join(root, 'evidence', 'images');
const credentials = JSON.parse(fs.readFileSync(path.join(runtime, 'credentials.json')));
const base = 'https://127.0.0.1:28443';
const channel = process.env.PLAYWRIGHT_CHANNEL;

async function main() {
  fs.mkdirSync(output, {recursive:true});
  const browser = await chromium.launch({headless:true,...(channel ? {channel} : {})});
  const results = [];
  const purpose = `Browser validation ${Date.now()}: customer analysis`;
  try {
    // Browser certificate trust bypass is LIMITED to this generated local demo CA.
    // Live HTTP E2E separately verifies chain and hostname without bypass.
    const context = await browser.newContext({ignoreHTTPSErrors:true, viewport:{width:1440,height:1100},
      clientCertificates:[{origin:base,certPath:path.join(runtime,'tls/company-device.crt'),keyPath:path.join(runtime,'tls/company-device.key')}]});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(base);
    await page.locator('#username').fill('analyst');
    await page.locator('#password').fill(credentials.analyst);
    await page.locator('#login button').click();
    await page.locator('#session').filter({hasText:'Tenant demo'}).waitFor();
    await page.locator('#read').click();
    await page.locator('#status.allow').waitFor();
    assert((await page.locator('#data').innerText()).includes('REDACTED'));
    await page.screenshot({path:path.join(output,'01-trusted-masking.png'),fullPage:true});
    results.push({name:'trusted UI masking',pass:true});
    const firstIds = await page.locator('#data tr').evaluateAll(rows => rows.slice(1).map(row => row.children[0].textContent));
    assert.equal(firstIds.length,25);
    await page.locator('#next-page').click();
    await page.waitForFunction(() => document.querySelector('#page-info').textContent.includes('Trang 2'));
    const secondIds = await page.locator('#data tr').evaluateAll(rows => rows.slice(1).map(row => row.children[0].textContent));
    assert.equal(secondIds.length,25);
    assert(secondIds.every(id => !firstIds.includes(id)));
    assert((await page.locator('#data').innerText()).includes('REDACTED'));
    await page.screenshot({path:path.join(output,'06-cursor-pagination.png'),fullPage:true});
    results.push({name:'bound cursor reads disjoint masked UI pages',pass:true});
    await page.locator('#load-catalog').click();
    await page.locator('#catalog').filter({hasText:'Cần phê duyệt thêm'}).waitFor();
    results.push({name:'catalog shows extra approval requirement',pass:true});
    await page.locator('#access-resource').selectOption('customers');
    await page.locator('#purpose').fill(purpose);
    await page.locator('#access-form button').click();
    await page.locator('#access-list tr').filter({hasText:purpose}).filter({hasText:'PENDING'}).waitFor();
    await page.screenshot({path:path.join(output,'07-access-request-pending.png'),fullPage:true});
    results.push({name:'analyst submits time-bound access request through UI',pass:true});
    await page.locator('#refresh-audit').click();
    await page.locator('#audit-list button').first().waitFor();
    await page.locator('#audit-list button').first().click();
    await page.waitForFunction(() => document.querySelector('#replay-result').textContent.includes('"status": "MATCH"'));
    await page.screenshot({path:path.join(output,'02-decision-replay.png'),fullPage:true});
    results.push({name:'historical replay through UI',pass:true});
    await page.locator('#logout').click();
    await page.waitForFunction(() => document.querySelector('#session').textContent.includes('Đã đăng xuất'));
    assert.equal(await page.locator('#data').innerText(),'');
    assert.equal(await page.locator('#audit-list').innerText(),'');
    results.push({name:'logout clears data and audit UI',pass:true});
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:path.join(output,'03-mobile.png'),fullPage:true});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    results.push({name:'mobile layout no page overflow',pass:true});
    await page.setViewportSize({width:1440,height:1100});
    await page.locator('#username').fill('admin');
    await page.locator('#password').fill(credentials.admin);
    await page.locator('#login button').click();
    await page.locator('#session').filter({hasText:'Tenant demo'}).waitFor();
    await page.locator('#refresh-access').click();
    const request = page.locator('#access-list tr').filter({hasText:purpose});
    await request.getByRole('button',{name:'Phê duyệt',exact:true}).click();
    await request.filter({hasText:'APPROVED'}).waitFor();
    await request.getByRole('button',{name:'Thu hồi',exact:true}).click();
    await request.filter({hasText:'REVOKED'}).waitFor();
    await page.screenshot({path:path.join(output,'08-access-grant-revoked.png'),fullPage:true});
    results.push({name:'independent tenant admin approves and revokes through UI',pass:true});
    await page.locator('#read').click();
    await page.locator('#status.allow').waitFor();
    const releases = path.join(runtime,'server/releases');
    const candidate = fs.readdirSync(releases).filter(name => /^[0-9a-f]{64}\.json$/.test(name))
      .map(name => JSON.parse(fs.readFileSync(path.join(releases,name))))
      .find(release => release.payload.view.mask_admin === true);
    assert(candidate, 'Live API checks must prepare a signed masking candidate first');
    await page.locator('#candidate').fill(candidate.revision);
    await page.locator('#impact').click();
    await page.waitForFunction(() => document.querySelector('#impact-result').textContent.includes('MASK_CHANGED'));
    await page.screenshot({path:path.join(output,'05-policy-impact.png'),fullPage:true});
    results.push({name:'admin policy impact through UI',pass:true});
    await page.locator('#logout').click();
    await page.waitForFunction(() => document.querySelector('#session').textContent.includes('Đã đăng xuất'));
    assert.deepEqual(errors, []);
    await context.close();
    // A nonmatching certificate origin explicitly declines mTLS for the Gateway.
    // This also prevents Edge from prompting for unrelated Windows-store certs.
    const stranger = await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:1100},
      clientCertificates:[{origin:'https://no-client-cert.invalid',certPath:path.join(runtime,'tls/company-device.crt'),keyPath:path.join(runtime,'tls/company-device.key')}]});
    const denied = await stranger.newPage();
    await denied.goto(base);
    await denied.locator('#username').fill('analyst');
    await denied.locator('#password').fill(credentials.analyst);
    await denied.locator('#login button').click();
    await denied.locator('#session').filter({hasText:'Tenant demo'}).waitFor();
    await denied.locator('#read').click();
    await denied.locator('#status.deny').waitFor();
    assert((await denied.locator('#status').innerText()).includes('UNTRUSTED_DEVICE'));
    assert.equal(await denied.locator('#data').innerText(),'');
    await denied.screenshot({path:path.join(output,'04-untrusted-device.png'),fullPage:true});
    results.push({name:'untrusted browser denied with no data',pass:true});
    await stranger.close();
  } finally {
    await browser.close();
    fs.writeFileSync(path.join(root,'evidence/browser.json'),JSON.stringify({executed_at:new Date().toISOString(),
      browser:channel ? `Playwright ${channel} (Chromium)` : 'Playwright Chromium',certificate_note:'Browser ignores locally generated server CA errors; client certificate is real. Python E2E verifies server CA.',checks:results,complete:results.length===10},null,2));
  }
  console.log(`${results.length}/${results.length} real browser checks passed`);
}
main().catch(error => {console.error(error.message); process.exitCode=1;});
