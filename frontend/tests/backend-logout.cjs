const assert = require("node:assert/strict");
const { chromium } = require("@playwright/test");

(async () => {
  const base = process.env.PERO_BROWSER_URL;
  assert.equal(new URL(base).hostname, "127.0.0.1");
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ locale: "zh-CN" });
    const page = await context.newPage();
    const login = async (username) => {
      await page.goto(`${base}/account/login`);
      await page.locator("[name=identifier]").fill(username);
      await page.locator("[name=password]").fill("BrowserTest123!");
      await Promise.all([
        page.waitForURL(`${base}/account/profile`),
        page.locator("form button[type=submit]").click(),
      ]);
      assert.ok((await context.cookies()).some((c) => c.name === "pero_sso"));
    };
    const hints = async () => {
      const response = await context.request.get(`${base}/__test/logout-hints`);
      assert.equal(response.status(), 200);
      return response.json();
    };
    const logoutURL = (token) =>
      `${base}/oauth2/session/end?id_token_hint=${encodeURIComponent(token)}`;
    await login("logout_user");
    const old = await hints();
    // Switching accounts leaves the RP with its previous identity token.
    await context.clearCookies();
    await login("logout_other");
    await page.goto(logoutURL(old.fresh));
    await page.getByRole("heading", { name: "确认退出登录" }).waitFor();
    assert.equal(
      await page.getByRole("heading", { name: "你已安全退出" }).count(),
      0,
    );
    await page.getByRole("link", { name: "取消并返回个人中心" }).click();
    await page.waitForURL(`${base}/account/profile`);
    await page.evaluate(({ base, hint }) => {
      const form = document.createElement("form");
      form.method = "POST";
      form.action = `${base}/oauth2/session/end`;
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "id_token_hint";
      input.value = hint;
      form.append(input);
      document.body.append(form);
      form.submit();
    }, { base, hint: old.fresh });
    await page.getByRole("heading", { name: "确认退出登录" }).waitFor();
    await Promise.all([
      page.getByRole("heading", { name: "你已安全退出" }).waitFor(),
      page.getByRole("button", { name: "确认退出", exact: true }).click(),
    ]);
    await page.getByRole("heading", { name: "你已安全退出" }).waitFor();
    assert.equal(
      (await context.cookies()).some((c) => c.name === "pero_sso"),
      false,
    );
    await page.goto(`${base}/account/profile`);
    await page.waitForURL(`${base}/account/login`);
    await page.getByRole("heading", { name: "欢迎回来" }).waitFor();
    await login("logout_user");
    const current = await hints();
    await page.goto(logoutURL(current.expired));
    await page.getByRole("heading", { name: "你已安全退出" }).waitFor();
    assert.equal(
      (await context.cookies()).some((c) => c.name === "pero_sso"),
      false,
    );
    console.log(
      "browser: login, account switch, cancellation, HTML POST confirmation and expired-hint logout passed",
    );
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
