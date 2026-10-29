import { test, expect, type Page } from "@playwright/test";

for (const kind of ["apps", "providers"] as const) {
  test(`editing ${kind} preserves required read-only fields in the request`, async ({
    page,
  }) => {
    const path = `/dashboard/${kind}/item-1/edit`;
    const form =
      kind === "apps"
        ? { code: "alpha", name: "Original", app_type: "web" }
        : {
            code: "oidc",
            name: "Original",
            kind: "oidc",
            issuer: "https://issuer.example.test",
            client_id: "client-1",
            userinfo_endpoint: "https://issuer.example.test/userinfo",
          };
    await mock(page, {
      [path]: {
        view: kind === "apps" ? "AppFormView" : "ProviderFormView",
        data: { ...base, mode: "edit", form },
      },
    });
    await page.goto(path);
    await expect(
      page.getByRole("textbox", {
        name: kind === "apps" ? "应用标识" : "提供方标识",
        exact: true,
      }),
    ).toBeDisabled();
    await page
      .getByRole("textbox", {
        name: kind === "apps" ? "应用名称" : "显示名称",
        exact: true,
      })
      .fill("Renamed");
    const submitted = page.waitForRequest(
      (r) => r.method() === "POST" && r.url().endsWith(path),
    );
    await page.getByRole("button", { name: "保存更改", exact: true }).click();
    const values = Object.fromEntries(
      new URLSearchParams((await submitted).postData()!),
    );
    expect(values).toMatchObject({
      ...form,
      name: "Renamed",
      csrf_token: "csrf-test",
    });
  });
}

const layout = {
  user_name: "成员",
  user_username: "member",
  can_access_dashboard: true,
  admin_access: {
    super_admin: true,
    revision: 0,
    global_permissions: [],
    app_grants: {},
  },
};
const base = { layout, csrf_token: "csrf-test" };

test("provider creation offers only supported protocols and local provider details have no edit entry", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/providers/new": {
      view: "ProviderFormView",
      data: { ...base, mode: "create", form: {} },
    },
    "/dashboard/providers/local": {
      view: "ProviderDetailView",
      data: {
        ...base,
        provider: {
          id: "local",
          name: "本地账户",
          code: "local",
          kind: "local",
          enabled: true,
        },
        keys: [],
      },
    },
  });
  await page.goto("/dashboard/providers/new");
  await page.getByRole("combobox", { name: "协议类型" }).click();
  await expect(page.getByRole("option")).toHaveCount(3);
  await expect(page.getByRole("option", { name: "本地账号" })).toHaveCount(0);
  await page.keyboard.press("Escape");
  await page.goto("/dashboard/providers/local");
  await expect(
    page.getByRole("link", { name: "编辑", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "添加密钥", exact: true }),
  ).toBeVisible();
});

test("registration completion and flow reset cannot run together", async ({
  page,
}) => {
  const enrollment = {
    view: "EnrollmentView",
    data: {
      csrf_token: "csrf-test",
      mode: "self_service",
      status: "ready",
      social: false,
      email: "member@example.test",
    },
  };
  let release!: () => void;
  let pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/*", async (route) => {
    if (!route.request().headers().accept?.includes("application/json"))
      return route.continue();
    if (route.request().method() === "POST") {
      await pending;
      return route.fulfill({ json: { error: "invalid_credentials" } });
    }
    return route.fulfill({ json: enrollment });
  });
  await page.goto("/sso/register");
  const finalize = page.getByRole("button", { name: "完成注册或确认加入" });
  const reset = page.getByRole("button", { name: "退出本次注册流程" });
  await finalize.click();
  await expect(reset).toBeDisabled();
  release();
  await expect(finalize).toBeEnabled();
  pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  await reset.click();
  await expect(finalize).toBeDisabled();
  await expect(
    page.getByRole("textbox", { name: "用户名", exact: true }),
  ).toBeDisabled();
  release();
  await expect(finalize).toBeEnabled();
});

const progress = {
  rows: [
    {
      id: "request-1",
      app_id: "app-1",
      app_name: "内部应用",
      email: "member@example.test",
      invitation: false,
      status: "pending_approval",
      reason: "",
      created_at: "2026-10-28T08:00:00Z",
      expires_at: "2026-10-29T08:00:00Z",
    },
  ],
  page: 1,
  total_pages: 6,
  pending_count: 105,
};

test("a closed application registration can exit the current flow", async ({
  page,
}) => {
  let activeFlow = true;
  await page.route("**/*", async (route) => {
    const request = route.request();
    if (!request.headers().accept?.includes("application/json"))
      return route.continue();
    if (request.method() === "POST") {
      expect(
        Object.fromEntries(new URLSearchParams(request.postData()!)),
      ).toEqual({
        action: "reset",
        csrf_token: "csrf-test",
      });
      activeFlow = false;
      return route.fulfill({ json: { redirect: "/sso/register" } });
    }
    return route.fulfill({
      json: {
        view: "EnrollmentView",
        data: {
          csrf_token: "csrf-test",
          mode: activeFlow ? "closed" : "self_service",
          status: activeFlow ? "ready" : "",
        },
      },
    });
  });
  await page.goto("/sso/register");
  await expect(page.getByText("注册已关闭", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "退出本次注册流程" }).click();
  await expect(
    page.getByRole("textbox", { name: "邮箱", exact: true }),
  ).toBeVisible();
});

async function mock(page: Page, responses: Record<string, unknown>) {
  await page.route("**/*", (route) => {
    const r = route.request(),
      u = new URL(r.url());
    if (!r.headers().accept?.includes("application/json"))
      return route.continue();
    return route.fulfill({
      json: r.method() === "POST" ? { code: 0 } : responses[u.pathname],
    });
  });
}
test("approval filtering, rejection reasons and owner progress use the expected requests", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/registration": {
      view: "EnrollmentAdminView",
      data: {
        ...base,
        ...progress,
        policy: {
          id: "app-1",
          app_id: "app-1",
          mode: "self_service",
          domains: [],
          approval_required: true,
          emergency_stop: false,
          version: 1,
        },
        inherited: false,
      },
    },
    "/account/applications": {
      view: "AdmissionView",
      data: { ...base, rows: [], username: "member", progress },
    },
  });
  await page.goto("/dashboard/registration?app=app-1&page=3");
  await expect(page.getByText("待审批 105 项")).toBeVisible();
  await page.getByLabel("搜索邮箱或应用").fill("member");
  await page.getByRole("button", { name: "查询", exact: true }).click();
  await expect(page).toHaveURL(/app=app-1&q=member/);
  expect(new URL(page.url()).searchParams.has("page")).toBeFalsy();
  await page.getByRole("button", { name: "拒绝", exact: true }).click();
  await page.getByRole("textbox", { name: "拒绝原因" }).fill("资料需要补充");
  const rejected = page.waitForRequest((r) => r.method() === "POST");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "保存更改", exact: true })
    .click();
  expect(new URLSearchParams((await rejected).postData()!).get("reason")).toBe(
    "资料需要补充",
  );
  await page.goto("/account/applications");
  await expect(page.getByText("我的申请与邀请")).toBeVisible();
  const continued = page.waitForRequest((r) => r.method() === "POST");
  await page.getByRole("button", { name: "继续办理", exact: true }).click();
  expect((await continued).url()).toContain("/account/enrollments/request-1");
});
test("members, audit details and account selection render their actions", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/apps/app-1/members": {
      view: "AppMembersView",
      data: {
        ...base,
        app_id: "app-1",
        app_name: "内部应用",
        system: false,
        page: 1,
        total_pages: 1,
        rows: [
          {
            user_id: "user-1",
            username: "member",
            nickname: "成员",
            status: "active",
          },
        ],
      },
    },
    "/dashboard/audit/event-1": {
      view: "AuditDetailView",
      data: {
        ...base,
        event: {
          id: "event-1",
          actor_id: "admin",
          actor_username: "admin",
          action: "/dashboard/apps/{id}/edit",
          target: "/dashboard/apps/app-1/edit",
          outcome: "success",
          http_status: 200,
          created_at: "2026-10-28T08:00:00Z",
          details: { name: { before: "旧名称", after: "新名称" } },
        },
      },
    },
    "/sso/select-account": {
      view: "SelectAccountView",
      data: {
        csrf_token: "csrf-test",
        username: "member",
        token: "signed-choice",
        redirect: "/account/profile",
      },
    },
  });
  await page.goto("/dashboard/apps/app-1/members");
  await page.getByLabel("完整用户名").fill("another");
  const granted = page.waitForRequest((r) => r.method() === "POST");
  await page.getByRole("button", { name: "授予访问资格", exact: true }).click();
  expect(new URLSearchParams((await granted).postData()!).get("username")).toBe(
    "another",
  );
  await page.goto("/dashboard/audit/event-1");
  await expect(page.getByText('"旧名称"')).toBeVisible();
  await expect(page.getByText('"新名称"')).toBeVisible();
  await page.goto("/sso/select-account?token=signed-choice");
  await expect(
    page.getByRole("button", { name: "继续使用 member" }),
  ).toBeVisible();
  const switched = page.waitForRequest((r) => r.method() === "POST");
  await page.getByRole("button", { name: "登录其他账号" }).click();
  const values = new URLSearchParams((await switched).postData()!);
  expect(values.get("action")).toBe("other");
  expect(values.get("token")).toBe("signed-choice");
  expect(values.get("csrf_token")).toBe("csrf-test");
});

test("administrator recovery and integration diagnostics expose the intended actions", async ({
  page,
}) => {
  const security = {
    view: "UserSecurityView",
    data: {
      ...base,
      user: { id: "user-1", username: "member" },
      mfa_enabled: true,
      can_recover: true,
      login_lock: {
        locked: true,
        failed_attempts: 5,
        retry_after_seconds: 600,
      },
      rows: [
        {
          id: "session-1",
          user_agent: "Test browser",
          ip: "127.0.0.1",
          current: false,
          authentication_pending: false,
          created_at: "2026-10-28T08:00:00Z",
          last_seen_at: "2026-10-28T08:00:00Z",
          expires_at: "2026-10-29T08:00:00Z",
        },
      ],
      page: 1,
      total_pages: 1,
    },
  };
  const integration = {
    view: "IntegrationView",
    data: {
      ...base,
      app: { id: "app-1", name: "Test app" },
      clients: [
        {
          id: "client-1",
          identifier: "test-client",
          type: "public",
          redirect_uris: ["https://client.example/callback"],
          scopes: ["openid"],
          grant_types: ["authorization_code"],
          status: "active",
        },
        {
          id: "client-2",
          identifier: "server-client",
          type: "confidential",
          redirect_uris: ["https://server.example/callback"],
          scopes: ["openid"],
          grant_types: ["authorization_code"],
          status: "active",
        },
      ],
      selected_client: "client-1",
      issuer: "https://issuer.example",
      callback_uri: "https://issuer.example/oauth2/diagnostic/callback",
      checks: [{ code: "test_callback", passed: false }],
      test: "",
      test_ready: false,
      test_success: false,
      error: "",
    },
  };
  await page.route("**/*", (route) => {
    const req = route.request(),
      u = new URL(req.url());
    if (!req.headers().accept?.includes("application/json"))
      return route.continue();
    if (req.method() === "POST")
      return route.fulfill({
        json: {
          code: 0,
          data: { secret: "one-time-recovery", purpose: "mfa_recovery" },
        },
      });
    return route.fulfill({
      json: u.pathname.endsWith("/security")
        ? security
        : u.searchParams.get("test") === "expired"
          ? {
              ...integration,
              data: { ...integration.data, error: "integration_test_expired" },
            }
          : {
              ...integration,
              data: {
                ...integration.data,
                selected_client: u.searchParams.get("client") || "client-1",
              },
            },
    });
  });
  await page.goto("/dashboard/users/user-1/security");
  await expect(
    page.getByText("密码登录已临时锁定，剩余 600 秒。", { exact: false }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "生成临时恢复码并退出全部会话", exact: true })
    .click();
  await page
    .getByRole("textbox", { name: "处理原因（勿填写密码或恢复码）" })
    .fill("ticket 123");
  const saving = page.waitForRequest((r) => r.method() === "POST");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "保存更改", exact: true })
    .click();
  const values = new URLSearchParams((await saving).postData()!);
  expect(values.get("action")).toBe("recover_mfa");
  expect(values.get("reason")).toBe("ticket 123");
  await expect(
    page.getByRole("textbox", { name: "临时恢复码", exact: true }),
  ).toHaveValue("one-time-recovery");
  await expect(page.getByRole("dialog")).toContainText("15 分钟");
  await page.getByRole("button", { name: "已保存，关闭" }).click();
  await page.goto("/dashboard/apps/app-1/integration");
  await expect(
    page.getByText("已登记诊断回调地址", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(/"token_endpoint_auth_method": "none"/),
  ).toBeVisible();
  await page
    .getByRole("combobox", { name: "OAuth 客户端", exact: true })
    .click();
  await page
    .getByRole("option", { name: "server-client", exact: true })
    .click();
  await expect(page).toHaveURL(/client=client-2/);
  await expect(page.getByText(/"client_id": "server-client"/)).toBeVisible();
  const currentUrl = page.url();
  const refreshed = page.waitForResponse(
    (r) =>
      r.request().method() === "GET" &&
      r.request().headers().accept?.includes("application/json") === true &&
      new URL(r.url()).pathname.endsWith("/integration"),
  );
  await page.getByText("刷新客户端列表", { exact: true }).click();
  expect(new URL((await refreshed).url()).searchParams.get("client")).toBe(
    "client-2",
  );
  await expect(page).toHaveURL(currentUrl);
  await expect(
    page.getByRole("combobox", { name: "OAuth 客户端", exact: true }),
  ).toHaveText("server-client");
  await page.getByRole("button", { name: "使用推荐配置创建客户端" }).click();
  await expect(page.getByRole("dialog")).toContainText("新建 OAuth 客户端");
  await expect(page.getByRole("dialog").getByLabel("权限范围")).toHaveValue(
    "openid,profile,email",
  );
  await page.goto("/dashboard/apps/app-1/integration?test=expired");
  await page.getByRole("link", { name: "重新开始诊断", exact: true }).click();
  await expect(page).toHaveURL(/\/integration$/);
  await expect(
    page.getByRole("button", { name: "开始测试登录", exact: true }),
  ).toBeVisible();
});

test("my applications filters authorized cards and opens configured homepages", async ({
  page,
}) => {
  await mock(page, {
    "/account/applications": {
      view: "AdmissionView",
      data: {
        ...base,
        username: "member",
        rows: [
          {
            id: "a",
            name: "设计协作",
            code: "design",
            description: "设计工具",
            status: "active",
            homepage_url: "https://design.example.test",
            logo_url: null,
          },
          {
            id: "b",
            name: "财务",
            code: "finance",
            status: null,
            homepage_url: "https://finance.example.test",
            logo_url: null,
          },
        ],
      },
    },
  });
  await page.goto("/account/applications");
  const open = page.getByRole("link", { name: "打开应用", exact: true });
  await expect(open).toHaveCount(1);
  await expect(open).toHaveAttribute("href", "https://design.example.test");
  await expect(open).toHaveAttribute("rel", "noopener noreferrer");
  await page.getByLabel("搜索应用").fill("finance");
  await expect(open).toHaveCount(0);
  await expect(page.getByText("暂无可用应用")).toBeVisible();
  await page.getByLabel("搜索应用").fill("DESIGN");
  await expect(open).toHaveCount(1);
});

test("permission assignment checks dependencies and submits explicit application grants", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/admins": {
      view: "AdminRolesView",
      data: {
        ...base,
        rows: [
          {
            user_id: "admin-1",
            username: "operator",
            role: "admin",
            grants: { revision: 2, global_permissions: [], app_grants: {} },
          },
        ],
        apps: [
          ["app-1", "alpha", "应用 A"],
          ["app-2", "beta", "应用 B"],
        ],
        catalog: [
          {
            code: "apps.read",
            scope: "app",
            name: "应用查询",
            dependencies: [],
            risk: "",
          },
          {
            code: "clients.read",
            scope: "app",
            name: "客户端查询",
            dependencies: ["apps.read"],
            risk: "",
          },
          {
            code: "clients.manage",
            scope: "app",
            name: "客户端管理",
            dependencies: ["clients.read"],
            risk: "高影响",
          },
        ],
      },
    },
  });
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/dashboard/admins/admin-1/permissions", async (route) => {
    await pending;
    await route.fulfill({ json: { code: 0 } });
  });
  await page.goto("/dashboard/admins");
  await page.getByRole("button", { name: "分配权限 · operator" }).click();
  await page.getByRole("combobox", { name: "选择应用", exact: true }).click();
  await page.getByRole("option", { name: "应用 A" }).click();
  await page
    .getByRole("checkbox", { name: "客户端管理 (clients.manage)", exact: true })
    .check();
  await expect(
    page.getByRole("checkbox", { name: "应用查询 (apps.read)", exact: true }),
  ).toBeChecked();
  await expect(
    page.getByRole("checkbox", {
      name: "客户端查询 (clients.read)",
      exact: true,
    }),
  ).toBeChecked();
  await page.getByRole("button", { name: "预览权限变更" }).click();
  const submitted = page.waitForRequest(
    (r) =>
      r.method() === "POST" &&
      r.url().endsWith("/dashboard/admins/admin-1/permissions"),
  );
  await page.getByRole("button", { name: "确认保存" }).click();
  await expect(
    page.getByRole("checkbox", {
      name: "客户端管理 (clients.manage)",
      exact: true,
    }),
  ).toBeDisabled();
  await expect(
    page.getByRole("combobox", { name: "选择应用", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "分配权限 · operator" }),
  ).toBeDisabled();
  release();
  expect((await submitted).postDataJSON()).toEqual({
    revision: 2,
    csrf_token: "csrf-test",
    global_permissions: [],
    app_grants: [
      {
        app_id: "app-1",
        permissions: ["apps.read", "clients.manage", "clients.read"],
      },
    ],
  });
});

test("administrator roles require a searched user and expose removal as an action", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/admins": {
      view: "AdminRolesView",
      data: {
        ...base,
        current_user_id: "admin-1",
        page: 1,
        total_pages: 1,
        apps: [],
        catalog: [],
        rows: [
          {
            user_id: "admin-1",
            username: "operator",
            role: "super_admin",
            grants: null,
          },
        ],
      },
    },
  });
  await page.route("**/dashboard/admins/users?q=*", (route) =>
    route.fulfill({
      json: {
        users: [
          { id: "admin-1", username: "operator" },
          { id: "user-2", username: "alice" },
        ],
      },
    }),
  );
  await page.goto("/dashboard/admins");
  await expect(
    page.getByRole("button", { name: "移除管理员", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "保存更改", exact: true }),
  ).toBeDisabled();
  await page.getByRole("combobox", { name: "搜索并选择用户" }).fill("ali");
  await expect(
    page.getByRole("option", { name: "operator", exact: true }),
  ).toHaveAttribute("aria-disabled", "true");
  await page.getByRole("option", { name: "alice", exact: true }).click();
  await page
    .getByRole("combobox", { name: "角色", exact: true })
    .last()
    .click();
  await expect(page.getByRole("option", { name: "移除管理员" })).toHaveCount(0);
  await page.getByRole("option", { name: "普通管理员", exact: true }).click();
  const submitted = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/dashboard/admins",
  );
  await page.getByRole("button", { name: "保存更改", exact: true }).click();
  expect(
    Object.fromEntries(new URLSearchParams((await submitted).postData()!)),
  ).toMatchObject({ username: "alice", role: "admin" });
  await page
    .getByRole("textbox", { name: "搜索用户名", exact: true })
    .fill("operator");
  await page
    .getByRole("textbox", { name: "搜索用户名", exact: true })
    .press("Enter");
  await expect(page).toHaveURL(/q=operator/);
  await page
    .getByRole("combobox", { name: "角色", exact: true })
    .first()
    .click();
  await page.getByRole("option", { name: "超级管理员", exact: true }).click();
  await expect(page).toHaveURL(/role=super_admin/);
  await page.screenshot({
    path: "test-results/admin-roles.png",
    fullPage: true,
  });
});

test("provider presets remain editable and switching clears protocol settings while preserving credentials", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/providers/new": {
      view: "ProviderFormView",
      data: { ...base, mode: "create", form: {} },
    },
  });
  await page.goto("/dashboard/providers/new");
  const choose = async (name: string) => {
    await page
      .getByRole("combobox", { name: "服务商预设", exact: true })
      .click();
    await page.getByRole("option", { name, exact: true }).click();
  };
  await choose("Google");
  await expect(page.getByLabel("Issuer", { exact: true })).not.toBeVisible();
  await expect(
    page.getByLabel("Client ID", { exact: true }),
  ).toHaveAccessibleDescription(/服务商应用控制台/);
  await expect(
    page.getByRole("checkbox", { name: "启用此身份提供方" }),
  ).toHaveAccessibleDescription(/草稿/);
  await page.screenshot({
    path: "test-results/provider-simple.png",
    fullPage: true,
  });
  await page
    .getByRole("button", { name: "可选与高级配置", exact: true })
    .click();
  await expect(page.getByLabel("Issuer", { exact: true })).toHaveValue(
    "https://accounts.google.com",
  );
  await page
    .getByLabel("Client ID", { exact: true })
    .fill("client-from-console");
  await page
    .getByLabel("Client Secret", { exact: true })
    .fill("secret-from-console");
  await page.getByRole("checkbox", { name: "启用此身份提供方" }).uncheck();
  await choose("Microsoft Entra ID");
  const tenant = page.getByRole("textbox", {
    name: "目录（租户）ID",
    exact: true,
  });
  await tenant.fill("common");
  expect(
    await tenant.evaluate((element: HTMLInputElement) =>
      element.checkValidity(),
    ),
  ).toBe(false);
  await expect(page.getByLabel("Issuer", { exact: true })).toHaveValue("");
  const tenantId = "11111111-2222-3333-4444-555555555555";
  await tenant.fill(tenantId);
  await expect(page.getByLabel("Issuer", { exact: true })).toHaveValue(
    `https://login.microsoftonline.com/${tenantId}/v2.0`,
  );
  await expect(page.getByLabel("令牌端点", { exact: true })).toHaveValue(
    `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
  );
  await expect(page.getByLabel("UserInfo 端点", { exact: true })).toHaveValue(
    "https://graph.microsoft.com/oidc/userinfo",
  );
  await expect(page.getByLabel("退出端点", { exact: true })).toHaveCount(0);
  await choose("GitHub");
  await expect(tenant).toHaveCount(0);
  await expect(page.getByLabel("退出端点", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("Issuer", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("JWKS URI", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("扩展配置 JSON", { exact: true })).toHaveValue(
    /api.github.com\/user\/emails/,
  );
  await choose("微信开放平台（网站扫码登录）");
  await expect(page.getByLabel("权限范围", { exact: true })).toHaveValue(
    "snsapi_login",
  );
  await expect(page.getByLabel("扩展配置 JSON", { exact: true })).toHaveCount(
    0,
  );
  await choose("GitLab.com");
  await expect(page.getByLabel("Client ID", { exact: true })).toHaveValue(
    "client-from-console",
  );
  await expect(page.getByLabel("Client Secret", { exact: true })).toHaveValue(
    "secret-from-console",
  );
  await expect(
    page.getByRole("checkbox", { name: "启用此身份提供方" }),
  ).not.toBeChecked();
  await page
    .getByRole("textbox", { name: "显示名称", exact: true })
    .fill("公司 GitLab");
  await page
    .getByLabel("授权端点", { exact: true })
    .fill("https://gitlab.example.test/oauth/authorize");
  await page.screenshot({
    path: "test-results/provider-preset.png",
    fullPage: true,
  });
  const submitted = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/dashboard/providers/new",
  );
  await page.getByRole("button", { name: "保存更改", exact: true }).click();
  expect(
    Object.fromEntries(new URLSearchParams((await submitted).postData()!)),
  ).toMatchObject({
    code: "gitlab",
    kind: "oidc",
    name: "公司 GitLab",
    issuer: "https://gitlab.com",
    authorization_endpoint: "https://gitlab.example.test/oauth/authorize",
    client_id: "client-from-console",
    client_secret: "secret-from-console",
    enabled: "false",
    scopes: "openid,profile,email",
    settings: "{}",
  });
});
