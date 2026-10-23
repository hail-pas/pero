import { test, expect, type Page } from "@playwright/test";
const layout = {
  user_name: "林知远",
  user_username: "lin",
  user_avatar_url: "",
  is_admin: true,
};
const user = {
  id: "u1",
  username: "lin",
  nickname: "林知远",
  email: "lin@example.com",
  phone: "+8613800000000",
  status: "active",
  has_password: true,
  email_verified: true,
  phone_verified: false,
  created_at: "2026-10-20T12:00:00Z",
};
const app = {
  id: "app-1",
  name: "团队协作平台",
  code: "workspace",
  type: "Web",
  status: "active",
  description: "让工作更有条理",
  created_at: "2026-10-20T12:00:00Z",
};
async function mock(page: Page, responses: Record<string, unknown> = {}) {
  await page.route("**/*", async (route) => {
    const req = route.request(),
      url = new URL(req.url());
    if (!req.headers().accept?.includes("application/json"))
      return route.continue();
    if (req.method() === "POST")
      return route.fulfill({
        json: { code: 0, ...((responses[url.pathname] as object) || {}) },
      });
    const view =
      url.pathname === "/"
        ? "HomeView"
        : url.pathname === "/account/login"
          ? "AccountLoginView"
          : url.pathname === "/account/profile"
            ? "ProfileView"
            : url.pathname === "/account/change-password"
              ? "ChangePasswordView"
              : url.pathname === "/dashboard/users"
                ? "UserListView"
                : url.pathname === "/dashboard/providers"
                  ? "ProviderListView"
                  : url.pathname.endsWith("/new")
                    ? "AppFormView"
                    : url.pathname === "/dashboard/apps/app-1"
                      ? "AppDetailView"
                      : "AppListView";
    await route.fulfill({
      json: responses[url.pathname] || {
        view,
        data: {
          layout,
          csrf_token: "csrf-test",
          user,
          has_password: true,
          apps: [app],
          users: [user],
          providers: [],
          page: 1,
          total_pages: 2,
          form: {},
          mode: "create",
          app,
          clients: [],
        },
      },
    });
  });
}
test("home and all main navigation routes render without runtime errors", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await mock(page);
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: /User Center/ }),
  ).toBeVisible();
  const filing = page.getByRole("link", { name: "渝ICP备2025069387号-1" });
  await expect(filing).toBeVisible();
  await expect(filing).toHaveAttribute("href", "https://beian.miit.gov.cn");
  await expect(filing).toHaveAttribute("target", "_blank");
  await page.goto("/account/login");
  await expect(filing).toBeVisible();
  for (const [path, title] of [
    ["/account/profile", "个人资料"],
    ["/account/change-password", "账户安全"],
    ["/dashboard/apps", "应用管理"],
    ["/dashboard/users", "用户管理"],
    ["/dashboard/providers", "身份提供方管理"],
    ["/dashboard/apps/new", "新建应用"],
  ]) {
    await page.goto(path);
    await expect(
      page.getByRole("heading", { name: title, exact: true }),
    ).toBeVisible();
  }
  expect(errors).toEqual([]);
});
test("server search resets pagination and preserves filters", async ({
  page,
}) => {
  await mock(page);
  await page.goto("/dashboard/apps?page=2&status=active");
  const search = page.getByPlaceholder("搜索应用，按 Enter 查询");
  await search.fill("workspace");
  await search.press("Enter");
  await expect(page).toHaveURL(/status=active&q=workspace/);
  expect(new URL(page.url()).searchParams.has("page")).toBeFalsy();
  await expect(page.getByText("团队协作平台", { exact: true })).toBeVisible();
});
test("workspace switches replace the old page without fading or moving its cards", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await mock(page);
  await page.goto("/account/profile");
  await expect(
    page.getByRole("heading", { name: "个人资料", exact: true }),
  ).toBeVisible();
  // Sample painted frames: screenshots normally wait for CSS animations to finish.
  await page.evaluate(() => {
    let unstable = 0;
    Object.assign(window, { workspaceUnstableFrames: () => unstable });
    function sample() {
      for (const card of document.querySelectorAll("main .MuiCard-root")) {
        const style = getComputedStyle(card);
        if (style.opacity !== "1" || style.transform !== "none") {
          unstable++;
        }
      }
      requestAnimationFrame(sample);
    }
    requestAnimationFrame(sample);
  });
  for (const [workspace, title, previous] of [
    ["管理工作空间", "应用管理", "个人资料"],
    ["个人工作空间", "个人资料", "应用管理"],
    ["管理工作空间", "应用管理", "个人资料"],
  ]) {
    await page.getByRole("button", { name: "切换工作空间" }).click();
    await page.getByRole("menuitem", { name: workspace, exact: true }).click();
    await expect(
      page.getByRole("heading", { name: title, exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: previous, exact: true }),
    ).toHaveCount(0);
  }
  expect(
    await page.evaluate(() =>
      (Reflect.get(window, "workspaceUnstableFrames") as () => number)(),
    ),
  ).toBe(0);
});
test("password mismatch is blocked before mutation", async ({ page }) => {
  await mock(page);
  await page.goto("/account/change-password");
  await page.locator('[name="old_password"]').fill("Current123!");
  await page.locator('[name="new_password"]').fill("New12345!");
  await page.locator('[name="confirm_password"]').fill("Other12345!");
  await page.getByRole("button", { name: "保存更改" }).click();
  await expect(
    page.getByRole("alert").filter({ hasText: "两次输入的密码不一致" }),
  ).toBeVisible();
});
test("contact change submits csrf and closes the dialog", async ({ page }) => {
  await mock(page);
  await page.goto("/account/profile");
  await page.getByRole("button", { name: "更换邮箱" }).click();
  await page.getByLabel("新邮箱").fill("new@example.com");
  const submitted = page.waitForRequest(
    (r) =>
      r.url().endsWith("/account/profile/change-email") &&
      r.method() === "POST",
  );
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "保存更改" })
    .click();
  const req = await submitted;
  expect(new URLSearchParams(req.postData()!).get("csrf_token")).toBe(
    "csrf-test",
  );
  expect(new URLSearchParams(req.postData()!).get("value")).toBe(
    "new@example.com",
  );
  await expect(page.getByRole("dialog")).not.toBeVisible();
});
test("client creation displays generated secret once", async ({ page }) => {
  await mock(page, {
    "/dashboard/clients/new": { data: { secret: "test-once-only-secret" } },
  });
  await page.goto("/dashboard/apps/app-1");
  await page.getByRole("button", { name: "添加客户端" }).click();
  await page.locator('[name="identifier"]').fill("new-client");
  await page
    .locator('[name="redirect_uris"]')
    .fill("https://example.com/callback");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "保存更改" })
    .click();
  await expect(
    page.getByRole("dialog").getByText("请保存客户端密钥"),
  ).toBeVisible();
  await expect(page.getByLabel("客户端密钥", { exact: true })).toHaveValue(
    "test-once-only-secret",
  );
  await page.getByRole("button", { name: "已保存，关闭" }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
});
test("login submits credentials and follows server redirect", async ({
  page,
}) => {
  await mock(page, {
    "/account/login": {
      view: "AccountLoginView",
      data: { csrf_token: "csrf-test", providers: [] },
    },
  });
  await page.route("**/account/login", async (route) => {
    if (route.request().method() === "POST")
      return route.fulfill({ json: { redirect: "/account/profile" } });
    return route.fallback();
  });
  await page.goto("/account/login");
  await page.locator('[name="identifier"]').fill("lin");
  await page.locator('[name="password"]').fill("Test123!");
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page).toHaveURL(/account\/profile$/);
  await expect(page.getByRole("heading", { name: "个人资料" })).toBeVisible();
});
test("forbidden response has a clear recoverable state", async ({ page }) => {
  await mock(page, {
    "/dashboard/apps": { view: "ForbiddenView", data: { code: "forbidden" } },
  });
  await page.goto("/dashboard/apps");
  await expect(page.getByRole("alert")).toContainText(
    "没有此工作空间的管理权限",
  );
  await expect(
    page.getByRole("link", { name: "返回首页" }).first(),
  ).toBeVisible();
});
test("mobile layout has accessible navigation without horizontal overflow", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mock(page);
  await page.goto("/account/profile");
  await page.getByRole("button", { name: "打开导航" }).click();
  await expect(page.getByRole("link", { name: "账户安全" })).toBeVisible();
  await page.getByRole("link", { name: "账户安全" }).click();
  await expect(
    page.getByRole("heading", { name: "账户安全", exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
});
test("visual review of desktop account and dashboard", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1080 });
  await mock(page);
  await page.goto("/account/profile");
  await expect(page.getByRole("heading", { name: "个人资料" })).toBeVisible();
  await page.screenshot({
    path: "test-results/account.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.goto("/dashboard/apps");
  await expect(page.getByRole("heading", { name: "应用管理" })).toBeVisible();
  await page.screenshot({
    path: "test-results/dashboard.png",
    fullPage: true,
    animations: "disabled",
  });
});

test("all remaining auth and recovery views render with their server context", async ({
  page,
}) => {
  await mock(page);
  const cases: [string, string, string, object][] = [
    ["/sso/register", "RegisterView", "创建你的账户", {}],
    ["/sso/forgot-password", "ForgotPasswordView", "找回密码", {}],
    [
      "/sso/reset-password?token=test",
      "ResetPasswordView",
      "设置新密码",
      { token: "test" },
    ],
    [
      "/sso/consent",
      "ConsentView",
      "授权应用访问",
      {
        request_token: "displayed-request-token",
        client_name: "团队协作平台",
        user_name: "林知远",
        scopes: ["openid", "profile", "email"],
      },
    ],
    [
      "/sso/social/link",
      "SocialLinkView",
      "关联已有账户",
      {
        nonce: "test-link",
        has_password: true,
        provider_name: "GitHub",
        account_email: "lin@example.com",
      },
    ],
    [
      "/sso/error?flow=logout",
      "ConfirmLogoutView",
      "确认退出登录",
      { session_id: "test-session", id_token_hint: "test-hint" },
    ],
    [
      "/account/profile/verify-contact?nonce=pending",
      "VerifyContactView",
      "验证联系方式",
      { nonce: "pending", masked_value: "l***@example.com", layout },
    ],
  ];
  for (const [path, view, title, extra] of cases) {
    await page.route(`**${path.split("?")[0]}*`, (route) => {
      if (route.request().headers().accept?.includes("application/json"))
        return route.fulfill({
          json: { view, data: { csrf_token: "csrf-test", ...extra } },
        });
      return route.fallback();
    });
    await page.goto(path);
    await expect(
      page.getByRole("heading", { name: title, exact: true }),
    ).toBeVisible();
    if (view === "ConsentView") {
      const submitted = page.waitForRequest(
        (r) =>
          r.method() === "POST" && new URL(r.url()).pathname === "/sso/consent",
      );
      await page.getByRole("button", { name: "允许访问", exact: true }).click();
      const request = await submitted;
      expect(
        new URLSearchParams(request.postData()!).get("request_token"),
      ).toBe("displayed-request-token");
    }
  }
});
test("provider key activation addresses the key identifier and asks for confirmation", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/providers/provider-1": {
      view: "ProviderDetailView",
      data: {
        layout,
        csrf_token: "csrf-test",
        provider: {
          id: "provider-1",
          code: "corp",
          name: "企业认证",
          kind: "oidc",
          enabled: true,
        },
        keys: [
          {
            id: "row-uuid",
            kid: "signing-2026",
            algorithm: "RS256",
            active: false,
          },
        ],
      },
    },
  });
  await page.goto("/dashboard/providers/provider-1");
  await page.getByRole("button", { name: "激活", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("激活密钥");
  const submitted = page.waitForRequest(
    (r) =>
      r.url().endsWith("/keys/signing-2026/activate") && r.method() === "POST",
  );
  await page.getByRole("button", { name: "确认", exact: true }).click();
  await submitted;
});
test("new app defaults to a valid type and server timestamps render as calendar dates", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/apps/new": {
      view: "AppFormView",
      data: {
        layout,
        csrf_token: "csrf-test",
        mode: "create",
        form: { code: "", name: "", app_type: "" },
      },
    },
    "/dashboard/apps": {
      view: "AppListView",
      data: {
        layout,
        csrf_token: "csrf-test",
        apps: [{ ...app, created_at: "2026-10-22T12:30:00Z" }],
        page: 1,
        total_pages: 1,
      },
    },
  });
  await page.goto("/dashboard/apps/new");
  await expect(page.getByRole("combobox", { name: "应用类型" })).toContainText(
    "Web 应用",
  );
  await page.goto("/dashboard/apps");
  await expect(page.getByRole("cell", { name: /2026-10-22/ })).toBeVisible();
});

test("language switch persists across navigation and reload without losing form edits", async ({
  page,
}) => {
  await mock(page);
  await page.goto("/account/profile");
  await page.locator('[name="nickname"]').fill("Unsubmitted edit");
  await page.getByRole("button", { name: "切换语言", exact: true }).click();
  await page.getByRole("menuitem", { name: /English/ }).click();
  await expect(
    page.getByRole("heading", { name: "Profile", exact: true }),
  ).toBeVisible();
  await expect(page.locator('[name="nickname"]')).toHaveValue(
    "Unsubmitted edit",
  );
  await expect(page.getByLabel("Nickname", { exact: true })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  expect(await page.evaluate(() => localStorage.getItem("pero.lang"))).toBe(
    "en",
  );
  await page.goto("/dashboard/apps");
  await expect(
    page.getByRole("heading", { name: "Applications", exact: true }),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Applications", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Change language", exact: true })
    .click();
  await page.getByRole("menuitem", { name: /简体中文/ }).click();
  await expect(
    page.getByRole("heading", { name: "应用管理", exact: true }),
  ).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
});
test("English forms, modals, validation and sign-in are fully localized", async ({
  page,
}) => {
  await page.addInitScript(() => localStorage.setItem("pero.lang", "en"));
  await mock(page);
  await page.goto("/account/profile");
  await page.getByRole("button", { name: "Change Email", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("New Email");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.goto("/account/change-password");
  await page.locator('[name="old_password"]').fill("Current123!");
  await page.locator('[name="new_password"]').fill("New12345!");
  await page.locator('[name="confirm_password"]').fill("Other12345!");
  await page.getByRole("button", { name: "Save Changes", exact: true }).click();
  await expect(
    page.getByRole("alert").filter({ hasText: /match/ }),
  ).toBeVisible();
  await page.goto("/dashboard/apps/new");
  await expect(
    page.getByRole("combobox", { name: /App Type|Application Type/ }),
  ).toContainText("Web application");
  expect(await page.locator("main").innerText()).not.toMatch(/[\u3400-\u9fff]/);
  await page.goto("/account/login");
  await expect(
    page.getByRole("heading", { name: "Welcome back", exact: true }),
  ).toBeVisible();
  await expect(page.locator('[name="password"]')).toHaveAttribute(
    "autocomplete",
    "current-password",
  );
  // The registered filing number stays unchanged in either language.
  const bodyText = await page.locator("body").innerText();
  expect(bodyText.replace("渝ICP备2025069387号-1", "")).not.toMatch(
    /[\u3400-\u9fff]/,
  );
});
test("language is available on mobile and errors from the backend use the selected language", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mock(page);
  await page.goto("/account/login");
  await page.getByRole("button", { name: "切换语言", exact: true }).click();
  await page.getByRole("menuitem", { name: /English/ }).click();
  await page.route("**/account/login", (route) =>
    route.request().method() === "POST"
      ? route.fulfill({ status: 400, json: { error: "invalid_credentials" } })
      : route.fallback(),
  );
  await page.locator('[name="identifier"]').fill("demo");
  await page.locator('[name="password"]').fill("Bad123!");
  await page
    .getByRole("button", { name: /Sign In|Log in|Login/, exact: true })
    .click();
  await expect(page.getByRole("alert")).not.toContainText("用户名");
  await expect(page.getByRole("alert")).toContainText(/password|credentials/i);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBeTruthy();
});

test("English visual review across account, dashboard and login", async ({
  page,
}) => {
  await page.addInitScript(() => localStorage.setItem("pero.lang", "en"));
  await page.setViewportSize({ width: 1440, height: 1000 });
  await mock(page);
  for (const [path, title, name] of [
    ["/account/profile", "Profile", "account-en"],
    ["/dashboard/apps", "Applications", "dashboard-en"],
    ["/account/login", "Welcome back", "login-en"],
  ]) {
    await page.goto(path);
    await expect(
      page.getByRole("heading", { name: title, exact: true }),
    ).toBeVisible();
    await page.screenshot({
      path: `test-results/${name}.png`,
      fullPage: true,
      animations: "disabled",
    });
  }
});

test("application type filtering and returning from registration preserve their request contracts", async ({
  page,
}) => {
  await mock(page, {
    "/sso/register": {
      view: "RegisterView",
      data: { csrf_token: "csrf-test", error: "" },
    },
    "/sso/login": {
      view: "LoginView",
      data: { csrf_token: "csrf-test", error: "", providers: [] },
    },
  });
  await page.goto("/dashboard/apps?page=2&status=active");
  await page.getByRole("combobox", { name: "类型", exact: true }).click();
  await page.getByRole("option", { name: "SPA", exact: true }).click();
  const params = new URL(page.url()).searchParams;
  expect(params.get("app_type")).toBe("spa");
  expect(params.get("status")).toBe("active");
  expect(params.has("page")).toBeFalsy();

  await page.goto("/sso/register");
  await page.getByRole("link", { name: "返回登录", exact: true }).click();
  await page.locator('[name="identifier"]').fill("test-user");
  await page.locator('[name="password"]').fill("Password123!");
  const login = page.waitForRequest(
    (r) => r.method() === "POST" && new URL(r.url()).pathname === "/sso/login",
  );
  await page.getByRole("button", { name: "登录", exact: true }).click();
  expect(new URLSearchParams((await login).postData()!).get("csrf_token")).toBe(
    "csrf-test",
  );
});

test("editing a client keeps its identifier immutable", async ({ page }) => {
  await mock(page, {
    "/dashboard/apps/app-1": {
      view: "AppDetailView",
      data: {
        layout,
        csrf_token: "csrf-test",
        app,
        clients: [
          {
            id: "client-1",
            identifier: "fixed-client",
            name: "Test client",
            type: "confidential",
            redirect_uris: ["https://example.com/callback"],
            post_logout_redirect_uris: [],
            scopes: ["openid"],
            grant_types: ["authorization_code"],
            require_pkce: true,
            access_token_ttl_seconds: 7200,
            refresh_token_ttl_seconds: 86400,
            id_token_ttl_seconds: 7200,
            status: "active",
          },
        ],
      },
    },
  });
  await page.goto("/dashboard/apps/app-1");
  await page.getByRole("button", { name: "编辑配置" }).click();
  await expect(
    page.getByRole("dialog").locator('[name="identifier"]'),
  ).toHaveCount(0);
  await page.getByRole("checkbox", { name: "要求 PKCE" }).uncheck();
  const request = page.waitForRequest((req) => req.method() === "POST");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "保存更改" })
    .click();
  const form = new URLSearchParams((await request).postData()!);
  expect(form.has("identifier")).toBe(false);
  expect(form.get("require_pkce")).toBe("false");
  expect(form.get("csrf_token")).toBe("csrf-test");
  await expect(page.getByRole("dialog")).not.toBeVisible();
});

test("malformed successful responses cannot report a saved profile", async ({
  page,
}) => {
  await mock(page);
  let validJson = false;
  await page.route("**/account/profile", (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    return validJson
      ? route.fulfill({ json: {} })
      : route.fulfill({
          contentType: "text/html",
          body: "<html>Proxy login</html>",
        });
  });
  await page.goto("/account/profile");
  for (const json of [false, true]) {
    validJson = json;
    await page.getByRole("button", { name: "保存更改", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText(
      "服务响应异常，请重试。",
    );
    await expect(page.getByText("操作已完成", { exact: true })).toHaveCount(0);
  }
});

test("navigation discards a previous page's secret dialog", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/clients/new": { data: { secret: "previous-page-secret" } },
  });
  await page.goto("/dashboard/apps");
  await page.getByText("团队协作平台", { exact: true }).click();
  await expect(page).toHaveURL(/\/dashboard\/apps\/app-1$/);
  await page.getByRole("button", { name: "添加客户端" }).click();
  await page.locator('[name="identifier"]').fill("new-client");
  await page
    .locator('[name="redirect_uris"]')
    .fill("https://example.com/callback");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "保存更改" })
    .click();
  await expect(page.getByLabel("客户端密钥", { exact: true })).toHaveValue(
    "previous-page-secret",
  );
  await page.goBack();
  await expect(
    page.getByRole("heading", { name: "应用管理", exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByText("previous-page-secret")).toHaveCount(0);
});

test("social-only accounts are guided to set a password before linking", async ({
  page,
}) => {
  await mock(page, {
    "/sso/social/link": {
      view: "SocialLinkView",
      data: {
        csrf_token: "csrf-test",
        nonce: "social-only",
        has_password: false,
        provider_name: "GitHub",
        account_email: "lin@example.com",
      },
    },
  });
  await page.goto("/sso/social/link?nonce=social-only");
  await expect(
    page.getByText("此账户尚未设置密码。", { exact: false }),
  ).toBeVisible();
  await expect(page.getByLabel("已有账户密码")).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: "登录原账户并设置密码" }),
  ).toHaveAttribute(
    "href",
    "/account/login?redirect=%2Faccount%2Fchange-password",
  );
});

test("security pages preserve confirmations, ownership contracts and event filters", async ({
  page,
}) => {
  const base = {
    layout,
    csrf_token: "csrf-test",
    page: 1,
    total_pages: 2,
    event_type: "",
  };
  const timestamp = "2026-10-23T08:00:00Z";
  await mock(page, {
    "/account/sessions": {
      view: "SessionListView",
      data: {
        ...base,
        rows: [
          {
            id: "session-1",
            ip: "127.0.0.1",
            user_agent: "Test browser",
            current: true,
            created_at: timestamp,
            last_seen_at: timestamp,
            expires_at: timestamp,
          },
        ],
      },
    },
    "/account/activity": {
      view: "ActivityListView",
      data: {
        ...base,
        rows: [
          {
            id: "event-1",
            username: "lin",
            event_type: "login_success",
            provider_name: "",
            ip: "127.0.0.1",
            user_agent: "Test browser",
            created_at: timestamp,
          },
        ],
      },
    },
    "/account/authorizations": {
      view: "AuthorizationListView",
      data: {
        ...base,
        rows: [
          {
            client_id: "client-1",
            app_id: "app-1",
            app_name: "团队协作平台",
            client_name: "Web",
            scopes: ["openid", "email"],
            granted_at: timestamp,
          },
        ],
      },
    },
    "/account/identities": {
      view: "IdentityListView",
      data: {
        ...base,
        error: "",
        has_password: true,
        rows: [
          {
            id: "identity-1",
            provider_name: "GitHub",
            enabled: true,
            last_login_at: timestamp,
          },
        ],
        providers: [{ key: "oidc", name: "Company SSO" }],
      },
    },
    "/dashboard/audit": {
      view: "AuditListView",
      data: {
        ...base,
        outcome: "",
        rows: [
          {
            id: "audit-1",
            actor_username: "lin",
            target: "/dashboard/users/user-1/reset-password",
            outcome: "success",
            http_status: 200,
            ip: "127.0.0.1",
            created_at: timestamp,
          },
        ],
      },
    },
  });
  await page.goto("/account/sessions");
  await expect(page.getByText("当前设备", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "退出其他设备", exact: true }).click();
  const revoke = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      request.url().endsWith("/account/sessions/revoke"),
  );
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "确认", exact: true })
    .click();
  const body = new URLSearchParams((await revoke).postData() || "");
  expect(body.get("scope")).toBe("others");
  expect(body.get("csrf_token")).toBe("csrf-test");
  await page.goto("/account/activity?page=2");
  await expect(page.getByText("登录成功", { exact: true })).toBeVisible();
  await page.getByLabel("事件类型").click();
  await page.getByRole("option", { name: "登录失败", exact: true }).click();
  await expect(page).toHaveURL(/event_type=login_failure/);
  expect(new URL(page.url()).searchParams.has("page")).toBe(false);
  await page.goto("/account/authorizations");
  await page.getByRole("button", { name: "撤销应用授权", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("所有客户端");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "取消", exact: true })
    .click();
  await page.goto("/account/identities");
  await expect(page.getByText("GitHub", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Company SSO", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("绑定到当前账户");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "取消", exact: true })
    .click();
  await page.goto("/dashboard/audit");
  await expect(
    page.getByText("/dashboard/users/user-1/reset-password", { exact: true }),
  ).toBeVisible();
  await page.screenshot({ path: "test-results/audit.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/account/sessions");
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
});
