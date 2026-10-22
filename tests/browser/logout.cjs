const assert = require('node:assert/strict');
const { chromium } = require('playwright');

(async () => {
  const base = process.env.PERO_BROWSER_URL;
  assert.equal(new URL(base).hostname, '127.0.0.1');
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const login = async (username) => {
      await page.goto(`${base}/account/login`);
      await page.locator('[name=identifier]').fill(username);
      await page.locator('[name=password]').fill('BrowserTest123!');
      await Promise.all([
        page.waitForURL(`${base}/account/profile`),
        page.locator('form button[type=submit]').click(),
      ]);
      assert.ok((await context.cookies()).some(c => c.name === 'pero_sso'));
    };
    const hints = async () => {
      const response = await context.request.get(`${base}/__test/logout-hints`);
      assert.equal(response.status(), 200);
      return response.json();
    };
    const logoutURL = token => `${base}/oauth2/session/end?id_token_hint=${encodeURIComponent(token)}`;
    await login('logout_user');
    const old = await hints();
    // Switching accounts leaves the RP with its previous identity token.
    await context.clearCookies();
    await login('logout_other');
    await page.goto(logoutURL(old.fresh));
    await page.locator('[data-i18n="end_session.confirmTitle"]').waitFor();
    assert.equal(await page.locator('[data-i18n="end_session.title"]').count(), 0);
    await page.locator('[data-i18n="end_session.cancel"]').click();
    await page.waitForURL(`${base}/account/profile`);
    await page.goto(logoutURL(old.fresh));
    await Promise.all([
      page.waitForURL(`${base}/oauth2/session/end`),
      page.locator('button[name=confirm]').click(),
    ]);
    await page.locator('[data-i18n="end_session.title"]').waitFor();
    assert.equal((await context.cookies()).some(c => c.name === 'pero_sso'), false);
    await page.goto(`${base}/account/profile`);
    assert.equal(new URL(page.url()).pathname, '/account/login');
    await login('logout_user');
    const current = await hints();
    await page.goto(logoutURL(current.expired));
    await page.locator('[data-i18n="end_session.title"]').waitFor();
    assert.equal((await context.cookies()).some(c => c.name === 'pero_sso'), false);
    console.log('browser: login, account switch, cancellation, confirmation and expired-hint logout passed');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
