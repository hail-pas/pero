import { createServer as createHttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { createServer as createViteServer } from "vite";
import { test, expect, type Page } from "@playwright/test";
const layout = {
  user_name: "林知远",
  user_username: "lin",
  user_avatar_url: "",
  can_access_dashboard: true,
  admin_access: {
    super_admin: true,
    revision: 0,
    global_permissions: [],
    app_grants: {},
  },
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
            : url.pathname === "/account/security"
              ? "SecurityView"
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
          enabled: false,
          required: false,
          pending: false,
          recovery: false,
          secret: "",
          qr: "",
          codes: [],
          redirect: "/account/profile",
          error: "",
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
  await expect(page.locator('link[rel="icon"]')).toHaveAttribute(
    "href",
    /resources\/icons\/logo\.svg$/,
  );
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
  await mock(page, {
    "/dashboard": {
      view: "AppListView",
      data: {
        layout,
        csrf_token: "csrf-test",
        apps: Array.from({ length: 12 }, (_, i) => ({
          ...app,
          id: `app-${i}`,
        })),
        page: 1,
        total_pages: 1,
      },
    },
  });
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
  await page.setViewportSize({ width: 1440, height: 600 });
  await page.getByRole("link", { name: "返回个人中心", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "个人资料", exact: true }),
  ).toBeVisible();
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  const previousScroll = await page.evaluate(() => window.scrollY);
  expect(previousScroll).toBeGreaterThan(0);
  await page.getByRole("link", { name: "管理控制台", exact: true }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
  await page.goBack();
  await expect
    .poll(() => page.evaluate(() => window.scrollY))
    .toBe(previousScroll);
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
  let finish!: () => void;
  const pending = new Promise<void>((resolve) => {
    finish = resolve;
  });
  await page.route("**/account/profile/change-email", async (route) => {
    await pending;
    await route.fulfill({ json: { code: 0 } });
  });
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
  await expect(
    page.getByRole("dialog").getByRole("button", { name: "取消" }),
  ).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeVisible();
  finish();
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
  await page.keyboard.press("Escape");
  await expect(page.getByLabel("客户端密钥", { exact: true })).toHaveValue(
    "test-once-only-secret",
  );
  await page.mouse.click(5, 5);
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
  await page.getByRole("button", { name: "切换工作空间" }).click();
  await expect(page.getByRole("menu")).toHaveCount(1);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("link", { name: "账户安全" })).toBeVisible();
  await page.getByRole("link", { name: "账户安全" }).click();
  await expect(
    page.getByRole("heading", { name: "账户安全", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "打开导航" }).click();
  await page.getByRole("link", { name: "管理控制台", exact: true }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole("button", { name: "切换工作空间" })).toBeHidden();
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
    [
      "/sso/register",
      "EnrollmentView",
      "注册与应用准入",
      { mode: "self_service", status: "", app: null, sent: false },
    ],
    ["/sso/error?flow=ended", "EndSessionView", "你已安全退出", {}],
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
    if (view === "EndSessionView") {
      const home = page.getByRole("link", { name: "返回首页", exact: true });
      await expect(home).toHaveCount(1);
      await expect(home).toHaveClass(/MuiButton-contained/);
    }
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
  await page.setViewportSize({ width: 360, height: 800 });
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
            activate_at: "2026-12-01T00:00:00Z",
          },
        ],
      },
    },
  });
  await page.goto("/dashboard/providers/provider-1");
  expect(
    await page
      .getByRole("button", { name: "紧急撤销", exact: true })
      .evaluate(
        (button) =>
          button.getBoundingClientRect().right <=
          button.closest(".MuiCard-root")!.getBoundingClientRect().right,
      ),
  ).toBeTruthy();
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
      view: "EnrollmentView",
      data: {
        csrf_token: "csrf-test",
        mode: "self_service",
        status: "",
        app: null,
        sent: false,
      },
    },
    "/sso/login": {
      view: "LoginView",
      data: { csrf_token: "csrf-test", error: "", providers: [] },
    },
  });
  await page.goto("/dashboard/apps?page=2&status=active");
  await page.getByRole("combobox", { name: "类型", exact: true }).click();
  await page.getByRole("option", { name: "SPA", exact: true }).click();
  await expect(page).toHaveURL(/app_type=spa/);
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
            authentication_pending: false,
            created_at: timestamp,
            last_seen_at: timestamp,
            expires_at: timestamp,
          },
          {
            id: "session-pending",
            ip: "127.0.0.2",
            user_agent: "Unverified browser",
            current: false,
            authentication_pending: true,
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
  await expect(page.getByText("待完成身份验证", { exact: true })).toBeVisible();
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

test("MFA challenge offers recovery without exposing enrollment secrets", async ({
  page,
}) => {
  await mock(page, {
    "/sso/mfa": {
      view: "SecurityView",
      data: {
        csrf_token: "csrf-test",
        enabled: true,
        required: false,
        pending: true,
        recovery: false,
        has_password: true,
        secret: "",
        qr: "",
        codes: [],
        redirect: "/account/profile",
        error: "invalid_mfa_code",
        providers: [],
      },
    },
  });
  await page.goto("/sso/mfa");
  await expect(
    page.getByRole("button", { name: "使用恢复码", exact: true }),
  ).toBeVisible();
  await expect(page.getByLabel("验证器验证码")).toBeVisible();
  await expect(page.getByAltText("验证器二维码")).toHaveCount(0);
  await page.evaluate(() => localStorage.setItem("pero.lang", "en"));
  await page.reload();
  await expect(
    page.getByText("The code is invalid or already used. Enter a new code.", {
      exact: true,
    }),
  ).toBeVisible();
  await page.evaluate(() => localStorage.setItem("pero.lang", "zh-CN"));
  await page.reload();
  await page.screenshot({ path: "test-results/mfa.png", fullPage: true });
  let failSetup = true;
  await page.route("**/account/security", async (route) => {
    if (!route.request().headers().accept?.includes("application/json"))
      return route.continue();
    const setting = route.request().method() === "POST";
    if (setting && failSetup) {
      failSetup = false;
      return route.fulfill({
        status: 503,
        json: { error: "service_unavailable" },
      });
    }
    await route.fulfill({
      json: {
        view: "SecurityView",
        data: {
          layout,
          csrf_token: "csrf-test",
          enabled: false,
          required: false,
          pending: false,
          recovery: false,
          has_password: true,
          secret: setting ? "ENROLLMENT-KEY" : "",
          qr: "",
          codes: [],
          redirect: "/account/profile",
          error: "",
          providers: [],
        },
      },
    });
  });
  await page.goto("/account/security");
  await page.getByRole("button", { name: "开始设置", exact: true }).click();
  await expect(
    page.getByText("服务暂时不可用，请稍后再试", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "开始设置", exact: true }).click();
  await expect(page.getByAltText("验证器二维码")).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.route("**/account/reauth", async (route) => {
    if (!route.request().headers().accept?.includes("application/json"))
      return route.continue();
    await route.fulfill({
      json: {
        view: "SecurityView",
        data: {
          layout,
          csrf_token: "csrf-test",
          enabled: false,
          required: false,
          pending: false,
          recovery: false,
          has_password: false,
          secret: "",
          qr: "",
          codes: [],
          redirect: "/account/security",
          error: "",
          providers: [],
        },
      },
    });
  });
  await page.goto("/account/reauth");
  await expect(
    page.getByText(
      "请通过已验证联系方式设置本地密码，再登录完成身份验证。未配置恢复方式时，请联系管理员。",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "保存更改", exact: true }),
  ).toHaveCount(0);
});

test("notification operations filter records and confirm safe retries", async ({
  page,
}) => {
  const row = {
    id: "delivery-1",
    kind: "verify_contact",
    channel: "email",
    recipient: "***est",
    status: "retrying",
    attempts: 3,
    last_error: "http_error",
    http_status: 503,
    created_at: "2026-10-28T00:00:00Z",
    updated_at: "2026-10-28T00:01:00Z",
    can_retry: true,
  };
  await mock(page, {
    "/dashboard/notifications": {
      view: "NotificationListView",
      data: {
        layout,
        csrf_token: "csrf-test",
        enabled: true,
        summary: { pending: 1, overdue: 0, failing: 1 },
        rows: [
          row,
          { ...row, id: "delivery-2", status: "delivered", can_retry: false },
        ],
        page: 1,
        total_pages: 2,
      },
    },
  });
  await page.goto("/dashboard/notifications?page=2");
  await expect(
    page.getByRole("heading", { name: "通知投递", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("发送服务拒绝请求 503").first()).toBeVisible();
  await expect(
    page.getByRole("button", { name: "立即重试", exact: true }).nth(1),
  ).toBeDisabled();
  await page.getByRole("combobox", { name: "投递状态" }).click();
  await page.getByRole("option", { name: "重试中", exact: true }).click();
  await expect(page).toHaveURL(/status=retrying/);
  expect(new URL(page.url()).searchParams.has("page")).toBeFalsy();
  await page
    .getByRole("button", { name: "立即重试", exact: true })
    .first()
    .click();
  const sent = page.waitForRequest(
    (req) =>
      req.method() === "POST" &&
      req.url().endsWith("/dashboard/notifications/delivery-1/retry"),
  );
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "确认", exact: true })
    .click();
  expect((await sent).postData()).toContain("csrf_token=csrf-test");
});

test("admission pages preserve application policy and explicit account closure confirmation", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/registration": {
      view: "EnrollmentAdminView",
      data: {
        layout,
        csrf_token: "csrf-test",
        policy: {
          id: "app-1",
          app_id: "app-1",
          mode: "self_service",
          domains: ["example.com"],
          approval_required: true,
          emergency_stop: false,
          version: 2,
        },
        inherited: false,
        rows: [],
      },
    },
    "/account/applications": {
      view: "AdmissionView",
      data: {
        layout,
        csrf_token: "csrf-test",
        username: "lin",
        rows: [{ id: "app-1", name: "内部应用", status: "active" }],
      },
    },
  });
  await page.goto("/dashboard/registration?app=app-1");
  await expect(page.getByLabel("允许的邮箱域名")).toHaveValue("example.com");
  const saved = page.waitForRequest(
    (r) =>
      r.method() === "POST" &&
      new URL(r.url()).pathname === "/dashboard/registration",
  );
  await page.getByRole("button", { name: "保存更改", exact: true }).click();
  const values = new URLSearchParams((await saved).postData()!);
  expect(values.get("app")).toBe("app-1");
  expect(values.get("version")).toBe("2");
  await page.goto("/account/applications");
  await page.getByLabel("输入当前用户名确认").fill("lin");
  await page.getByRole("button", { name: "注销账户", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByText("确认删除个人资料并撤销全部访问资格？"),
  ).toBeVisible();
  const close = page.waitForRequest(
    (r) =>
      r.method() === "POST" && new URL(r.url()).pathname === "/account/close",
  );
  await dialog.getByRole("button", { name: "确认", exact: true }).click();
  expect(
    new URLSearchParams((await close).postData()!).get("confirmation"),
  ).toBe("lin");
});

test("security notices, cards and footer actions keep their spacing and alignment", async ({
  page,
}) => {
  await mock(page, {
    "/account/security": {
      view: "SecurityView",
      data: {
        layout,
        csrf_token: "csrf-test",
        enabled: false,
        required: true,
        pending: true,
        recovery: false,
        codes: [],
        secret: "",
        qr: "",
        redirect: "/account/profile",
        error: "",
      },
    },
  });
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/account/security");
    const notice = page.getByRole("alert");
    const card = page.locator("main .MuiCard-root");
    const setup = page.getByRole("button", { name: "开始设置", exact: true });
    await expect(setup).toBeVisible();
    const n = (await notice.boundingBox())!;
    const c = (await card.boundingBox())!;
    expect(c.y - n.y - n.height).toBeGreaterThanOrEqual(20);
    expect(c.height).toBeLessThan(200);
    await expect(page.locator("aside")).toHaveCount(0);
    await expect(
      page.getByRole("link", { name: "返回个人中心", exact: true }),
    ).toHaveCount(0);
    await page.screenshot({
      path: `test-results/security-spacing-${width}.png`,
      fullPage: true,
    });
    const logout = (await page
      .getByRole("main")
      .getByRole("button", { name: "退出登录", exact: true })
      .boundingBox())!;
    expect(logout.width).toBeGreaterThan(0);
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth),
    ).toBeLessThanOrEqual(width);
    await page.goto("/account/profile");
    await expect(
      page.getByRole("heading", { name: "个人资料", exact: true }),
    ).toBeVisible();
    const main = (await page.getByRole("main").boundingBox())!;
    const longFooter = (await page.locator("footer").boundingBox())!;
    expect(longFooter.y).toBeGreaterThanOrEqual(main.y + main.height - 1);
    await page.locator("footer").scrollIntoViewIfNeeded();
    await expect(page.locator("footer")).toBeVisible();
  }
});

test("HTTP login and MFA redirects commit the final route without an intermediate profile", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  const security = {
    view: "SecurityView",
    data: {
      layout,
      csrf_token: "csrf-test",
      enabled: false,
      required: true,
      pending: true,
      recovery: false,
      has_password: true,
      secret: "",
      qr: "",
      codes: [],
      redirect: "/account/profile",
      error: "",
      providers: [],
    },
  };
  // Browser routing does not intercept requests followed by an HTTP redirect.
  // Serve the final MFA response through a real backend and isolated Vite proxy.
  const backend = createHttpServer((_req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(security));
  });
  await new Promise<void>((resolve) => backend.listen(0, "127.0.0.1", resolve));
  const previousOrigin = process.env.PERO_API_ORIGIN;
  process.env.PERO_API_ORIGIN = `http://127.0.0.1:${(backend.address() as AddressInfo).port}`;
  const vite = await createViteServer({
    server: { host: "127.0.0.1", port: 0, strictPort: true },
  });
  try {
    await vite.listen();
    const origin = `http://127.0.0.1:${(vite.httpServer!.address() as AddressInfo).port}`;
    await mock(page, { "/sso/mfa": security });
    await page.route("**/account/login", (route) =>
      route.request().method() === "POST"
        ? route.fulfill({ status: 303, headers: { Location: "/sso/mfa" } })
        : route.fallback(),
    );
    await page.goto(`${origin}/account/login`);
    await page.locator('[name="identifier"]').fill("lin");
    await page.locator('[name="password"]').fill("Password123!");
    await page.getByRole("button", { name: "登录", exact: true }).click();
    await expect(page).toHaveURL(/\/sso\/mfa$/);
    await expect(
      page.getByRole("heading", { name: "设置验证器", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "返回个人中心", exact: true }),
    ).toHaveCount(0);
    await expect(page.locator("aside")).toHaveCount(0);
    await expect(
      page.getByRole("heading", { name: "个人资料", exact: true }),
    ).toHaveCount(0);
  } finally {
    await vite.close();
    await new Promise<void>((resolve, reject) =>
      backend.close((error) => (error ? reject(error) : resolve())),
    );
    if (previousOrigin === undefined) delete process.env.PERO_API_ORIGIN;
    else process.env.PERO_API_ORIGIN = previousOrigin;
  }
});

test("slow navigation and refresh preserve the current page and mounted workspace", async ({
  page,
}) => {
  await mock(page);
  await page.goto("/account/profile");
  const heading = page.getByRole("heading", { name: "个人资料", exact: true });
  await expect(heading).toBeVisible();
  await page.evaluate(() =>
    Object.assign(window, { originalMain: document.querySelector("main") }),
  );
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/account/security", async (route) => {
    await pending;
    await route.fallback();
  });
  await page.locator('a[href="/account/security"]').first().click();
  await expect(
    page.getByRole("progressbar", { name: "正在加载", exact: true }),
  ).toBeVisible();
  await expect(heading).toBeVisible();
  await expect(page.locator(".MuiSkeleton-root")).toHaveCount(0);
  release();
  await expect(page).toHaveURL(/\/account\/security$/);
  await expect(
    page.getByRole("heading", { name: "设置验证器", exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () =>
        document.querySelector("main") === Reflect.get(window, "originalMain"),
    ),
  ).toBe(true);
  await page.locator('a[href="/account/profile"]').first().click();
  await expect(heading).toBeVisible();
  let finishRefresh!: () => void;
  const refreshing = new Promise<void>((resolve) => {
    finishRefresh = resolve;
  });
  await page.route("**/account/profile", async (route) => {
    if (route.request().method() === "GET") await refreshing;
    await route.fallback();
  });
  await page.getByRole("button", { name: "保存更改", exact: true }).click();
  await expect(
    page.getByRole("progressbar", { name: "正在加载", exact: true }),
  ).toBeVisible();
  await expect(heading).toBeVisible();
  await expect(page.locator(".MuiSkeleton-root")).toHaveCount(0);
  finishRefresh();
  await expect(
    page.getByRole("button", { name: "保存更改", exact: true }),
  ).toBeEnabled();
  await expect(
    page.getByRole("progressbar", { name: "正在加载", exact: true }),
  ).toHaveCount(0);
});

test("login failures have one owner, preserve inputs and use refreshed CSRF on retry", async ({
  page,
}) => {
  await mock(page, {
    "/account/login": {
      view: "AccountLoginView",
      data: {
        csrf_token: "csrf-test",
        providers: [],
        error: "invalid_credentials",
      },
    },
  });
  let attempts = 0;
  await page.route("**/account/login", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    attempts++;
    if (attempts === 1)
      return route.fulfill({
        json: {
          view: "AccountLoginView",
          data: {
            csrf_token: "csrf-refreshed",
            providers: [],
            error: "invalid_credentials",
          },
        },
      });
    expect(
      new URLSearchParams(route.request().postData()!).get("csrf_token"),
    ).toBe("csrf-refreshed");
    return route.fulfill({ json: { redirect: "/account/profile" } });
  });
  await page.goto("/account/login");
  await expect(page.getByRole("alert")).toHaveCount(1);
  await page.locator('[name="identifier"]').fill("lin");
  await expect(page.getByRole("alert")).toHaveCount(0);
  await page.locator('[name="password"]').fill("Wrong-password");
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveCount(1);
  await expect(page.getByRole("alert")).toBeFocused();
  await expect(page.locator('[name="identifier"]')).toHaveValue("lin");
  await expect(page.locator('[name="password"]')).toHaveValue("Wrong-password");
  await page.getByRole("button", { name: "切换语言" }).click();
  await page.getByRole("menuitem", { name: /English/ }).click();
  await expect(page.getByRole("alert")).toHaveText("Invalid credentials");
  await expect(page.getByRole("menu")).toHaveCount(0);
  await expect(page.locator(".MuiMenu-root")).toHaveCount(0);
  await page.screenshot({
    path: "test-results/login-feedback.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Sign In", exact: true }).click();
  await expect(page).toHaveURL(/account\/profile$/);
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("MFA view errors appear once and clear after editing", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 600 });
  const data = {
    layout,
    csrf_token: "csrf-test",
    enabled: true,
    required: true,
    pending: true,
    recovery: false,
    codes: [],
    providers: [],
    error: "",
    redirect: "/account/profile",
  };
  await mock(page, { "/sso/mfa": { view: "SecurityView", data } });
  let finish!: () => void;
  const pending = new Promise<void>((resolve) => {
    finish = resolve;
  });
  await page.route("**/sso/mfa", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    await pending;
    return route.fulfill({
      json: {
        view: "SecurityView",
        data: { ...data, error: "invalid_mfa_code" },
      },
    });
  });
  await page.goto("/sso/mfa");
  await page.getByLabel("验证器验证码").fill("000000");
  await page.getByRole("button", { name: "验证并继续" }).click();
  await expect(
    page.getByRole("textbox", { name: "恢复码", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "使用恢复码", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "退出登录", exact: true }).last(),
  ).toBeDisabled();
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  finish();
  const errors = page
    .getByRole("alert")
    .filter({ hasText: "验证码无效或已使用" });
  await expect(errors).toHaveCount(1);
  await expect(errors).toBeFocused();
  await expect(errors).toBeInViewport();
  await expect(
    page.getByRole("textbox", { name: "恢复码", exact: true }),
  ).toBeEnabled();
  await page.getByLabel("验证器验证码").fill("123456");
  await expect(errors).toHaveCount(0);
});

test("network and malformed response failures are readable and recover on retry", async ({
  page,
}) => {
  await mock(page, {
    "/account/login": {
      view: "AccountLoginView",
      data: { csrf_token: "csrf-test", providers: [] },
    },
  });
  let attempts = 0;
  await page.route("**/account/login", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    attempts++;
    if (attempts === 1) return route.abort("failed");
    if (attempts === 2)
      return route.fulfill({
        contentType: "application/json",
        body: "{invalid",
      });
    return route.fulfill({ json: { redirect: "/account/profile" } });
  });
  await page.goto("/account/login");
  await page.locator('[name="identifier"]').fill("lin");
  await page.locator('[name="password"]').fill("Test123!");
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveText(
    "网络连接失败，请检查网络后重试。",
  );
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveText("服务响应异常，请重试。");
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page).toHaveURL(/account\/profile$/);
});

test("a business policy rejection keeps the editor and its input available", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/apps/new": {
      view: "AppFormView",
      data: {
        layout,
        mode: "create",
        form: {},
        csrf_token: "csrf-test",
        error: "code_exists",
      },
    },
  });
  let attempts = 0;
  await page.route("**/dashboard/apps/new", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    if (++attempts > 1) return route.fulfill({ json: { code: 0 } });
    return route.fulfill({
      status: 403,
      json: { error: "registration_closed" },
    });
  });
  await page.goto("/dashboard/apps/new");
  await expect(page.getByRole("alert")).toHaveText("编码已存在");
  await page.locator('[name="code"]').fill("new-app");
  await page.locator('[name="name"]').fill("新应用");
  await page.getByRole("button", { name: "保存更改" }).click();
  await expect(page.getByRole("alert")).toHaveCount(1);
  await expect(page.getByRole("heading", { name: "新建应用" })).toBeVisible();
  await expect(page.locator('[name="code"]')).toHaveValue("new-app");
  await expect(page.getByRole("alert")).toHaveText(
    "此入口暂未开放注册，请联系管理员。",
  );
  await page.getByRole("button", { name: "保存更改" }).click();
  await expect(page).toHaveURL(/dashboard\/apps$/);
  await expect(page.getByRole("alert")).toHaveText("操作已完成");
  await page.getByText("团队协作平台", { exact: true }).click();
  await expect(page).toHaveURL(/dashboard\/apps\/app-1$/);
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("late forbidden mutations cannot replace a page after leaving and returning", async ({
  page,
}) => {
  await mock(page);
  let finish!: () => void;
  const responseReady = new Promise<void>((resolve) => {
    finish = resolve;
  });
  await page.route("**/dashboard/clients/new", async (route) => {
    await responseReady;
    await route.fulfill({ status: 403, json: { error: "forbidden" } });
  });
  await page.goto("/dashboard/apps");
  await page.getByText("团队协作平台", { exact: true }).click();
  await page.getByRole("button", { name: "添加客户端" }).click();
  await page.locator('[name="identifier"]').fill("new-client");
  await page
    .locator('[name="redirect_uris"]')
    .fill("https://example.com/callback");
  const requestStarted = page.waitForRequest((r) => r.method() === "POST");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "保存更改" })
    .click();
  await requestStarted;
  await page.goBack();
  await expect(
    page.getByRole("heading", { name: "应用管理", exact: true }),
  ).toBeVisible();
  await page.goForward();
  await expect(
    page.getByRole("heading", { name: "团队协作平台", exact: true }),
  ).toBeVisible();
  const completed = page.waitForResponse(
    (r) => r.request().method() === "POST",
  );
  finish();
  await completed;
  // Let the fetch promise and React state updates drain before checking the page.
  await page.evaluate(
    () =>
      new Promise((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(resolve)),
      ),
  );
  await expect(
    page.getByRole("heading", { name: "团队协作平台", exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("unusable reset links offer recovery instead of a password form", async ({
  page,
}) => {
  let error = "missing_token";
  await mock(page, {
    "/sso/forgot-password": {
      view: "ForgotPasswordView",
      data: { csrf_token: "csrf-test", error: "", success: false },
    },
  });
  await page.route("**/sso/reset-password*", (route) => {
    if (!route.request().headers().accept?.includes("application/json"))
      return route.fallback();
    return route.fulfill({
      json: {
        view: "ResetPasswordView",
        data: {
          csrf_token: "csrf-test",
          token: "reset-token",
          error,
          success: "",
        },
      },
    });
  });
  for (const code of ["missing_token", "invalid_token", "token_already_used"]) {
    error = code;
    await page.goto("/sso/reset-password?token=reset-token");
    await expect(page.locator("form")).toHaveCount(0);
    await expect(page.getByRole("alert")).toBeVisible();
    await expect(
      page.getByRole("link", { name: "重新申请重置链接" }),
    ).toHaveAttribute("href", "/sso/forgot-password");
  }
  // Policy errors remain editable; an expired token returned on submit does not.
  error = "password_mismatch";
  await page.goto("/sso/reset-password?token=reset-token");
  await page.locator('[name="new_password"]').fill("Test123!");
  await page.locator('[name="confirm_password"]').fill("Test123!");
  error = "invalid_token";
  await page.getByRole("button", { name: "保存新密码" }).click();
  await expect(page.locator("form")).toHaveCount(0);
  await expect(page.getByRole("alert")).toHaveText("重置链接无效或已过期");
  await page.getByRole("link", { name: "重新申请重置链接" }).click();
  await expect(page).toHaveURL(/\/sso\/forgot-password$/);
  await expect(
    page.getByRole("button", { name: "发送恢复通知" }),
  ).toBeVisible();
});

test("successful password reset removes the consumed-token form", async ({
  page,
}) => {
  await mock(page, {
    "/sso/reset-password": {
      view: "ResetPasswordView",
      data: {
        csrf_token: "csrf-test",
        token: "reset-token",
        error: "",
        success: "",
      },
    },
  });
  await page.route("**/sso/reset-password?token=reset-token", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    return route.fulfill({
      json: {
        view: "ResetPasswordView",
        data: {
          csrf_token: "csrf-test",
          error: "",
          success: "password_reset_success",
        },
      },
    });
  });
  await page.goto("/sso/reset-password?token=reset-token");
  await page.locator('[name="new_password"]').fill("Test123!");
  await page.locator('[name="confirm_password"]').fill("Test123!");
  await page.getByRole("button", { name: "保存新密码" }).click();
  await expect(page.getByRole("alert")).toHaveText("密码已更新，请返回登录。");
  await expect(page.locator("form")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "返回登录" })).toBeVisible();
});

for (const refreshFirst of [true, false]) {
  test(`an in-flight refresh cannot discard recovery codes: refresh first ${refreshFirst}`, async ({
    page,
  }) => {
    const data = {
      layout,
      csrf_token: "csrf-test",
      enabled: true,
      required: true,
      pending: false,
      recovery: false,
      secret: "",
      qr: "",
      codes: [],
      providers: [],
      error: "",
      redirect: "/account/profile",
    };
    await mock(page);
    let reads = 0;
    let releaseRefresh!: () => void;
    let releaseMutation!: () => void;
    const refreshing = new Promise<void>((resolve) => {
      releaseRefresh = resolve;
    });
    const mutating = new Promise<void>((resolve) => {
      releaseMutation = resolve;
    });
    await page.route("**/account/security", async (route) => {
      if (!route.request().headers().accept?.includes("application/json"))
        return route.fallback();
      if (route.request().method() === "POST") {
        await mutating;
        return route.fulfill({
          json: {
            view: "SecurityView",
            data: { ...data, codes: ["fresh-one-time-recovery-code"] },
          },
        });
      }
      if (++reads === 2) await refreshing;
      return route.fulfill({
        json: {
          view: "SecurityView",
          data: {
            ...data,
            layout: {
              ...layout,
              user_name: reads > 1 ? "refreshed-account" : layout.user_name,
            },
          },
        },
      });
    });
    await page.goto("/account/security");
    await page.getByLabel("验证器验证码").fill("123456");
    const refreshStarted = page.waitForRequest(
      (r) => r.method() === "GET" && r.url().endsWith("/account/security"),
    );
    await page.evaluate(() => window.dispatchEvent(new Event("focus")));
    await refreshStarted;
    const mutationStarted = page.waitForRequest((r) => r.method() === "POST");
    await page.getByRole("button", { name: "重新生成恢复码" }).click();
    await mutationStarted;
    const refreshCompleted = page.waitForResponse(
      (r) =>
        r.request().method() === "GET" && r.url().endsWith("/account/security"),
    );
    if (refreshFirst) {
      releaseRefresh();
      await expect(
        page.getByText("refreshed-account", { exact: true }).first(),
      ).toBeVisible();
      await page.evaluate(() => window.dispatchEvent(new Event("focus")));
      releaseMutation();
    } else {
      releaseMutation();
      await expect(
        page.getByText("fresh-one-time-recovery-code", { exact: true }),
      ).toBeVisible();
      releaseRefresh();
    }
    await (await refreshCompleted).finished();
    await page.evaluate(
      () =>
        new Promise((resolve) =>
          requestAnimationFrame(() => requestAnimationFrame(resolve)),
        ),
    );
    await expect(
      page.getByText("fresh-one-time-recovery-code", { exact: true }),
    ).toBeVisible();
    expect(reads).toBe(2);
  });
}

test("expired MFA setup accepts the server state and allows restarting", async ({
  page,
}) => {
  const data = {
    layout,
    csrf_token: "csrf-test",
    enabled: false,
    required: false,
    pending: false,
    recovery: false,
    secret: "expired-setup-secret",
    qr: "",
    codes: [],
    providers: [],
    error: "",
    redirect: "/account/profile",
  };
  await mock(page, { "/account/security": { view: "SecurityView", data } });
  await page.route("**/account/security", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    const action = new URLSearchParams(route.request().postData()!).get(
      "action",
    );
    return route.fulfill({
      json: {
        view: "SecurityView",
        data: {
          ...data,
          secret: action === "setup" ? "fresh-setup-secret" : "",
          error: action === "setup" ? "" : "invalid_request",
        },
      },
    });
  });
  await page.goto("/account/security");
  await page.getByLabel("验证器验证码").fill("123456");
  await page.getByRole("button", { name: "启用双重验证" }).click();
  await expect(page.getByRole("alert")).toHaveCount(1);
  await expect(
    page.getByText("expired-setup-secret", { exact: true }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "开始设置" }).click();
  await expect(
    page.getByText("fresh-setup-secret", { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("recovery retries clear previous success before reporting a new failure", async ({
  page,
}) => {
  await mock(page, {
    "/sso/forgot-password": {
      view: "ForgotPasswordView",
      data: { csrf_token: "csrf-test", error: "", success: false },
    },
  });
  let attempts = 0;
  await page.route("**/sso/forgot-password", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    if (++attempts === 1)
      return route.fulfill({
        json: {
          view: "ForgotPasswordView",
          data: { csrf_token: "csrf-test", error: "", success: true },
        },
      });
    return route.abort("failed");
  });
  await page.goto("/sso/forgot-password");
  await page.getByLabel("邮箱或完整手机号").fill("lin@example.com");
  await page.getByRole("button", { name: "发送恢复通知" }).click();
  await expect(
    page.getByText("如果账户可恢复，你将收到重置密码的通知。", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "发送恢复通知" }).click();
  await expect(
    page.getByText("网络连接失败，请检查网络后重试。", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("如果账户可恢复，你将收到重置密码的通知。", { exact: true }),
  ).toHaveCount(0);
});

test("consent errors from a previous action do not duplicate the next form error", async ({
  page,
}) => {
  await mock(page, {
    "/sso/consent": {
      view: "ConsentView",
      data: {
        csrf_token: "csrf-test",
        request_token: "request-test",
        client_name: "示例应用",
        user_name: "lin",
        user_email: "",
        scopes: ["openid"],
      },
    },
  });
  await page.route("**/sso/consent", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    return route.abort("failed");
  });
  await page.goto("/sso/consent");
  await page.getByRole("button", { name: "拒绝授权" }).click();
  const errors = page.getByRole("alert").filter({ hasText: "网络连接失败" });
  await expect(errors).toHaveCount(1);
  await page.getByRole("button", { name: "允许访问" }).click();
  await expect(page.locator("form").getByRole("alert")).toHaveCount(1);
  await expect(errors).toHaveCount(1);
});
