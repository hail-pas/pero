import { test, expect, type Page } from "@playwright/test";

const layout = {
  user_name: "管理员",
  user_username: "admin",
  user_avatar_url: "",
  can_access_dashboard: true,
  admin_access: {
    super_admin: true,
    revision: 0,
    global_permissions: [],
    app_grants: {},
  },
};
const base = { layout, csrf_token: "csrf-test" };

async function mock(page: Page, responses: Record<string, unknown> = {}) {
  let posts = 0;
  await page.route("**/*", async (route) => {
    const request = route.request();
    if (!request.headers().accept?.includes("application/json"))
      return route.continue();
    if (request.method() === "POST") {
      posts++;
      return route.fulfill({ json: { code: 0 } });
    }
    const path = new URL(request.url()).pathname;
    await route.fulfill({
      json: responses[path] || {
        view: "AppListView",
        data: { ...base, apps: [], page: 1, total_pages: 1 },
      },
    });
  });
  return () => posts;
}

test("application form renders organization fields only for organization modes", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/apps/new": {
      view: "AppFormView",
      data: { ...base, mode: "create", form: {}, error: "" },
    },
  });
  await page.goto("/dashboard/apps/new");
  const tenantMode = page.getByRole("combobox", { name: "租户模式", exact: true });
  const organizationAccess = page.getByRole("combobox", {
    name: "组织准入规则",
    exact: true,
  });
  const automaticAccess = page.getByRole("checkbox", {
    name: "组织成员首次登录自动开通应用资格",
    exact: true,
  });
  await expect(tenantMode).toBeVisible();
  await expect(organizationAccess).toHaveCount(0);
  await expect(automaticAccess).toHaveCount(0);

  await tenantMode.click();
  await page.getByRole("option", { name: "组织空间", exact: true }).click();
  await expect(organizationAccess).toBeVisible();
  await expect(automaticAccess).toBeVisible();

  await tenantMode.click();
  await page.getByRole("option", { name: "个人空间", exact: true }).click();
  await expect(organizationAccess).toHaveCount(0);
  await expect(automaticAccess).toHaveCount(0);

  const sessionLimit = page.getByRole("combobox", {
    name: "设备登录限制",
    exact: true,
  });
  await expect(page.getByLabel("最大登录设备数")).toBeVisible();
  await sessionLimit.click();
  await page.getByRole("option", { name: "关闭限制", exact: true }).click();
  await expect(page.getByLabel("最大登录设备数")).toHaveCount(0);
});

test("application form blocks invalid dependent values before submitting", async ({
  page,
}) => {
  const posts = await mock(page, {
    "/dashboard/apps/new": {
      view: "AppFormView",
      data: { ...base, mode: "create", form: {}, error: "" },
    },
  });
  await page.goto("/dashboard/apps/new");
  await page
    .getByRole("textbox", { name: "应用标识", exact: true })
    .fill("alpha");
  await page
    .getByRole("textbox", { name: "应用名称", exact: true })
    .fill("Alpha");
  await page
    .getByRole("spinbutton", { name: "最大登录设备数", exact: true })
    .fill("0");
  await page.getByRole("button", { name: "保存更改", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("请输入有效的正整数");
  expect(posts()).toBe(0);
});

test("client editor hides secret and ID token fields when not applicable", async ({
  page,
}) => {
  const client = {
    id: "client-1",
    identifier: "web",
    name: "Web",
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
  };
  await mock(page, {
    "/dashboard/apps/app-1": {
      view: "AppDetailView",
      data: {
        ...base,
        app: {
          id: "app-1",
          name: "Team",
          code: "team",
          status: "active",
          description: "",
          created_at: "2026-10-20T12:00:00Z",
        },
        clients: [client],
        invitation_domains: null,
        all_apps: [],
        access_list: [],
        identities: [],
      },
    },
  });
  await page.goto("/dashboard/apps/app-1");
  await expect(page.getByRole("button", { name: "邀请开户", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "添加客户端", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByLabel("Client Secret", { exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByLabel("ID Token 有效期（秒）", { exact: true }),
  ).toBeVisible();

  await dialog
    .getByRole("combobox", { name: "客户端类型", exact: true })
    .click();
  await page.getByRole("option", { name: "公开客户端", exact: true }).click();
  await expect(dialog.getByLabel("Client Secret", { exact: true })).toHaveCount(
    0,
  );

  await dialog.getByLabel("权限范围", { exact: true }).fill("profile");
  await expect(
    dialog.getByLabel("ID Token 有效期（秒）", { exact: true }),
  ).toHaveCount(0);
});

test("inherited registration policy reveals configuration only when detached", async ({
  page,
}) => {
  await mock(page, {
    "/dashboard/registration": {
      view: "EnrollmentAdminView",
      data: {
        ...base,
        policy: {
          app_id: "app-1",
          mode: "self_service",
          domains: [],
          approval_required: true,
          emergency_stop: false,
          version: 1,
        },
        inherited: true,
        can_invite: true,
        rows: [],
        page: 1,
        total_pages: 1,
        pending_count: 0,
      },
    },
  });
  await page.goto("/dashboard/registration");
  const inherit = page.getByRole("checkbox", {
    name: "继承平台默认策略",
    exact: true,
  });
  await expect(inherit).toBeChecked();
  await expect(
    page.getByText("当前应用继承平台默认策略。取消勾选后可单独配置。", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("combobox", { name: "注册模式", exact: true }),
  ).toHaveCount(0);

  await inherit.uncheck();
  const mode = page.getByRole("combobox", {
    name: "注册模式",
    exact: true,
  });
  await expect(mode).toBeVisible();
  await expect(page.getByLabel("允许的邮箱域名")).toBeVisible();

  await mode.click();
  await page.getByRole("option", { name: "仅邀请", exact: true }).click();
  await expect(page.getByLabel("允许的邮箱域名")).toBeVisible();

  await mode.click();
  await page.getByRole("option", { name: "关闭", exact: true }).click();
  await expect(page.getByLabel("允许的邮箱域名")).toHaveCount(0);
});
