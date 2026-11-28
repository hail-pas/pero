import { test, expect, type Page } from "@playwright/test";

for (const kind of ["apps", "providers"] as const) {
  test(`editing ${kind} preserves required read-only fields in the request`, async ({
    page,
  }) => {
    const path = `/dashboard/${kind}/item-1/edit`;
    const form =
      kind === "apps"
        ? { code: "alpha", name: "Original" }
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
  const finalize = page.getByRole("button", { name: "创建账号" });
  const reset = page.getByRole("button", { name: "退出本次注册流程" });
  await page.getByRole("textbox", { name: "用户名", exact: true }).fill("member");
  await page.getByLabel(/^密码\s*\*?$/).fill("ValidPass123!");
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

test("registration translates field guidance and existing errors without clearing the form", async ({
  page,
}) => {
  const requests: string[] = [];
  await page.route("**/sso/register", async (route) => {
    const request = route.request();
    if (!request.headers().accept?.includes("application/json"))
      return route.continue();
    if (request.method() === "POST") {
      requests.push(request.headers()["accept-language"]);
      return route.fulfill({
        status: 400,
        json: {
          error:
            requests.length === 1
              ? "username can only contain letters, digits, underscore, and hyphen"
              : "password must be at least 12 characters",
        },
      });
    }
    return route.fulfill({
      json: {
        view: "EnrollmentView",
        data: {
          mode: "self_service",
          status: "ready",
          email: "member@example.test",
          flow: "register-flow",
          csrf_token: "csrf-test",
          password_policy: {
            min_length: 12,
            max_length: 64,
            require_uppercase: true,
            require_lowercase: false,
            require_digit: false,
            require_special: true,
          },
        },
      },
    });
  });
  await page.goto("/sso/register");
  const username = page.locator('[name="username"]');
  const password = page.locator('[name="password"]');
  await expect(password).toHaveAccessibleDescription(
    "密码长度为 12–64 个字符。 密码需包含大写字母和特殊字符。",
  );
  await username.fill("中文名");
  await password.fill("short");
  await page.getByRole("button", { name: "创建账号" }).click();
  const characterError = "用户名只能包含英文字母、数字、下划线和连字符";
  await expect(username).toHaveAccessibleDescription(characterError);
  expect(requests).toEqual([]);
  await username.fill("valid_name");
  await page.getByRole("button", { name: "创建账号" }).click();
  await expect(page.getByRole("alert").getByText(characterError)).toBeVisible();

  await page.getByRole("button", { name: "切换语言" }).click();
  await page.getByRole("menuitem", { name: /English/ }).click();
  await expect(
    page
      .getByRole("alert")
      .getByText(
        "Use only English letters, digits, underscores, and hyphens in your username",
      ),
  ).toBeVisible();
  await expect(password).toHaveAccessibleDescription(
    "Use 12–64 characters. Include an uppercase letter and a special character.",
  );
  await expect(username).toHaveValue("valid_name");
  await expect(password).toHaveValue("short");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(
    page
      .getByRole("alert")
      .getByText("Password must be at least 12 characters"),
  ).toBeVisible();
  expect(requests).toEqual(["zh-CN", "en"]);
  await page.getByRole("button", { name: "Change language" }).click();
  await page.getByRole("menuitem", { name: /简体中文/ }).click();
  await expect(
    page.getByRole("alert").getByText("密码长度至少 12 个字符"),
  ).toBeVisible();
});

test("phone registration localizes verification, approval, and an unknown resend error", async ({
  page,
}) => {
  let data = {
    csrf_token: "csrf-test",
    flow: "phone-flow",
    mode: "self_service",
    phone: "",
    status: "",
    can_act: false,
    can_resend: true,
    allowed_methods: ["phone"],
  };
  await page.route("**/sso/register", async (route) => {
    const request = route.request();
    if (!request.headers().accept?.includes("application/json"))
      return route.continue();
    if (request.method() === "POST") {
      const values = new URLSearchParams(request.postData()!);
      if (values.get("action") === "resend") {
        return route.fulfill({
          status: 400,
          json: { error: "unexpected_internal_result" },
        });
      }
      data = {
        ...data,
        phone: values.get("phone")!,
        status: "pending_verification",
      };
    }
    return route.fulfill({ json: { view: "EnrollmentView", data } });
  });
  await page.goto("/sso/register");
  await page.getByRole("button", { name: "切换语言" }).click();
  await page.getByRole("menuitem", { name: /English/ }).click();
  await expect(
    page.getByText("Verify your phone number to complete registration."),
  ).toBeVisible();
  const phone = page.locator('[name="phone"]');
  const send = page.getByRole("button", { name: "Send verification SMS" });
  await phone.fill("1234567");
  await send.click();
  await expect(phone).toHaveAccessibleDescription(
    /Enter a phone number with its country code/,
  );
  await phone.fill("+8613800000000");
  await send.click();
  await expect(
    page.getByText(
      "The verification text has been queued. Open the link in the text to continue.",
    ),
  ).toBeVisible();
  await page.getByRole("button", { name: "Resend the link" }).click();
  await expect(
    page.getByText("Unable to complete the request. Please try again."),
  ).toBeVisible();

  data = { ...data, status: "pending_approval" };
  await page.reload();
  await expect(page.getByText(/Your phone number is verified/)).toContainText(
    "you’ll receive the result by text message",
  );
  await expect(
    page.getByRole("button", { name: "Change language" }),
  ).toBeVisible();
});

test("stale manual invitations direct the user to the administrator", async ({ page }) => {
  await mock(page, {
    "/sso/register": {
      view: "EnrollmentView",
      data: {
        csrf_token: "csrf-test",
        flow: "invite-flow",
        mode: "invite_only",
        status: "pending_verification",
        email: "invited@example.test",
        manual_delivery: true,
        can_act: false,
      },
    },
  });
  await page.goto("/sso/register");
  const notice = page.getByRole("alert");
  await expect(notice).toHaveText("请联系发出邀请的管理员，获取最新的邀请链接。");
  await page.getByRole("button", { name: "切换语言" }).click();
  await page.getByRole("menuitem", { name: /English/ }).click();
  await expect(notice).toHaveText(
    "Contact the administrator who invited you for the latest invitation link.",
  );
});

test("social registration localizes callback failures and requires email for verification", async ({
  page,
}) => {
  await mock(page, {
    "/sso/register": {
      view: "EnrollmentView",
      data: {
        mode: "self_service",
        social: true,
        status: "",
        error: "userinfo_failed",
        allowed_methods: ["email", "phone"],
        flow: "social-flow",
        csrf_token: "csrf-test",
      },
    },
  });
  await page.goto("/sso/register?error=userinfo_failed");
  await expect(page.getByRole("alert")).toHaveText(
    "无法获取第三方账户信息，请重试或选择其他登录方式。",
  );
  await page.getByRole("button", { name: "切换语言" }).click();
  await page.getByRole("menuitem", { name: /English/ }).click();
  await expect(page.getByRole("alert")).toHaveText(
    "Could not retrieve your account details from the provider. Try again or choose another sign-in method.",
  );
  await expect(
    page.getByText(
      "Enter your email address and open the verification link to continue signing up with your provider.",
    ),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Send verification email" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Sign up with phone" }),
  ).toHaveCount(0);
});

test("the invitation registration form submits optional contact details", async ({ page }) => {
  await mock(page, {
    "/sso/register": {
      view: "EnrollmentView",
      data: {
        csrf_token: "csrf-test",
        flow: "invite-flow",
        mode: "invite_only",
        status: "ready",
        account_invitation: true,
      },
    },
  });
  await page.goto("/sso/register");
  await page.getByLabel("用户名", { exact: false }).fill("invited_user");
  await page.getByLabel(/^密码\s*\*?$/).fill("ValidPass123!");
  const email = page.getByRole("textbox", { name: "邮箱", exact: true });
  const phone = page.getByRole("textbox", { name: /手机号/ });
  await expect(email).not.toHaveAttribute("required");
  await expect(phone).not.toHaveAttribute("required");
  await email.fill("invitee@example.test");
  await phone.fill("+8613800000000");
  const submitted = page.waitForRequest((r) => r.method() === "POST");
  await page.getByRole("button", { name: "创建账号" }).click();
  expect(Object.fromEntries(new URLSearchParams((await submitted).postData()!))).toMatchObject({
    action: "finalize",
    email: "invitee@example.test",
    phone: "+8613800000000",
  });
});

test("self-service registration explains when no verification channel is available", async ({
  page,
}) => {
  await mock(page, {
    "/sso/register": {
      view: "EnrollmentView",
      data: {
        csrf_token: "csrf-test",
        mode: "self_service",
        status: "",
        allowed_methods: [],
        providers: [],
      },
    },
  });

  await page.goto("/sso/register");
  await expect(page.getByRole("alert")).toContainText(
    "当前没有可用的邮箱或短信验证渠道，暂时无法自助注册。请联系管理员。",
  );
  await expect(page.getByRole("textbox")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "返回登录" })).toBeVisible();
});

test("login from registration receives the scoped cookie and submits the flow", async ({
  page,
  context,
}) => {
  const flow = "registration-flow";
  await mock(page, {
    "/sso/register": {
      view: "EnrollmentView",
      data: {
        csrf_token: "enrollment-csrf",
        mode: "self_service",
        status: "ready",
        existing_account: true,
        flow,
      },
    },
    "/sso/register/login": {
      view: "AccountLoginView",
      data: {
        csrf_token: "login-csrf",
        redirect: "/sso/register",
        flow,
        providers: [],
      },
    },
  });
  await page.goto("/sso/register");
  await context.addCookies([
    {
      name: "pero_enrollment",
      value: "current",
      domain: new URL(page.url()).hostname,
      path: "/sso",
    },
  ]);
  await page.getByRole("link", { name: "登录已有账户" }).click();
  await expect(page).toHaveURL(/\/sso\/register\/login\?/);
  await page.reload();
  await page.locator('[name="identifier"]').fill("member");
  await page.locator('[name="password"]').fill("Password123!");
  const submitted = page.waitForRequest(
    (request) => request.method() === "POST",
  );
  await page.getByRole("button", { name: "登录", exact: true }).click();
  const request = await submitted;
  expect(new URL(request.url()).pathname).toBe("/sso/register/login");
  expect(await request.headerValue("cookie")).toContain(
    "pero_enrollment=current",
  );
  expect(new URLSearchParams(request.postData()!).get("flow")).toBe(flow);
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
        flow: "closed-application-flow",
      });
      activeFlow = false;
      return route.fulfill({ json: { redirect: "/account/applications" } });
    }
    return route.fulfill({
      json: {
        view: "EnrollmentView",
        data: {
          csrf_token: "csrf-test",
          mode: activeFlow ? "closed" : "self_service",
          status: activeFlow ? "ready" : "",
          flow: "closed-application-flow",
        },
      },
    });
  });
  await page.goto("/sso/register");
  await expect(page.getByText("注册已关闭", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "退出本次注册流程" }).click();
  await expect(page).toHaveURL(/\/account\/applications$/);
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
test("invitation delivery controls whether the email is shown and submitted", async ({
  page,
}) => {
  const path = "/dashboard/users/new";
  const link = "https://sso.example.test/sso/register?token=invitation";
  await mock(page, {
    [path]: {
      view: "UserFormView",
      data: {
        ...base,
        mode: "create",
        form: {},
        user_id: "",
        invitation_domains: ["example.test"],
      },
    },
  });
  await page.route(`**${path}`, (route) =>
    route.request().method() === "POST"
      ? route.fulfill({
          json: {
            code: 0,
            data: { secret: link, purpose: "invitation_activation" },
          },
        })
      : route.fallback(),
  );
  await page.goto(path);
  const delivery = page.getByRole("combobox", { name: "交付方式" });
  const email = page.getByRole("textbox", { name: "邀请邮箱" });
  const exception = page.getByRole("checkbox", { name: "允许此邀请超出域名限制" });
  const exceptionReason = page.getByRole("textbox", { name: "域名例外理由" });
  const note = page.getByRole("textbox", { name: "邀请说明" });
  await expect(email).toHaveAttribute("required", "");
  await note.fill("欢迎加入");
  await delivery.click();
  await page.getByRole("option", { name: "手动分享链接（指定邮箱）" }).click();
  await expect(email).toHaveAttribute("required", "");
  await email.fill("invitee@example.test");
  await expect(exception).toHaveCount(0);
  await expect(note).toHaveValue("欢迎加入");
  await email.fill("invitee@external.test");
  await exception.check();
  await exceptionReason.fill("仅供管理员查看");
  await email.fill("another@example.test");
  await expect(exceptionReason).toHaveCount(0);
  await expect(note).toHaveValue("欢迎加入");
  await email.fill("invitee@external.test");
  await expect(exceptionReason).toHaveValue("");
  await exception.check();
  await delivery.click();
  await page.getByRole("option", { name: "手动分享开户链接" }).click();
  await expect(email).toHaveCount(0);
  await expect(exception).not.toBeChecked();
  await page.getByRole("button", { name: "创建邀请" }).click();
  await expect(exception).toHaveAccessibleDescription("请勾选域名例外后再创建邀请。");
  await exception.check();
  await exceptionReason.fill("临时开户");
  const submitted = page.waitForRequest((r) => r.method() === "POST");
  await page.getByRole("button", { name: "创建邀请" }).click();
  const values = Object.fromEntries(new URLSearchParams((await submitted).postData()!));
  expect(values).toEqual({
    delivery: "account_link",
    domain_exception: "true",
    reason: "临时开户",
    csrf_token: "csrf-test",
  });
  const dialog = page.getByRole("dialog", { name: "邀请激活链接" });
  await expect(dialog.getByRole("textbox", { name: "激活链接" })).toHaveValue(link);
  await expect(dialog.getByRole("button", { name: "复制" })).toBeVisible();
});

test("app details issue account links scoped to the application", async ({ page }) => {
  const path = "/dashboard/apps/app-1";
  const link = "https://sso.example.test/sso/register?token=account-link";
  await mock(page, {
    [path]: {
      view: "AppDetailView",
      data: {
        ...base,
        app: { id: "app-1", code: "app", name: "App", status: "active", tenant_mode: "personal" },
        clients: [],
        invitation_domains: ["example.test"],
      },
    },
  });
  await page.route("**/dashboard/invitations", (route) => route.fulfill({
    json: { code: 0, data: { secret: link, purpose: "invitation_activation" } },
  }));
  await page.goto(path);
  await page.getByRole("button", { name: "邀请开户" }).click();
  const editor = page.getByRole("dialog", { name: "邀请开户" });
  await editor.getByRole("checkbox", { name: "允许此邀请超出域名限制" }).check();
  await editor.getByRole("textbox", { name: "域名例外理由" }).fill("临时开户");
  const submitted = page.waitForRequest((r) => r.method() === "POST");
  await editor.getByRole("button", { name: "保存更改" }).click();
  const values = new URLSearchParams((await submitted).postData()!);
  expect(Object.fromEntries(values)).toEqual({
    app: "app-1",
    delivery: "account_link",
    domain_exception: "true",
    reason: "临时开户",
    csrf_token: "csrf-test",
  });
  await expect(page.getByRole("textbox", { name: "激活链接" })).toHaveValue(link);
});

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
        can_invite: true,
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
test("enrollment dialogs update their labels and instructions when another tab changes language", async ({
  page,
  context,
}) => {
  await mock(page, {
    "/dashboard/registration": {
      view: "EnrollmentAdminView",
      data: {
        ...base,
        ...progress,
        rows: [
          ...progress.rows,
          {
            ...progress.rows[0],
            id: "invite-1",
            invitation: true,
            status: "ready",
          },
        ],
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
        can_invite: true,
      },
    },
  });
  await page.goto("/dashboard/registration");
  await page.getByRole("button", { name: "切换语言" }).click();
  await page.getByRole("menuitem", { name: /English/ }).click();
  await page.getByRole("button", { name: "Get activation link" }).click();

  const otherTab = await context.newPage();
  await mock(otherTab, { "/": { view: "HomeView", data: {} } });
  await otherTab.goto("/");
  await otherTab.getByRole("button", { name: "Change language" }).click();
  await otherTab.getByRole("menuitem", { name: /简体中文/ }).click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByRole("heading", { name: "获取激活链接" }),
  ).toBeVisible();
  await expect(
    dialog.getByText("将签发新链接，旧链接会立即失效。"),
  ).toBeVisible();
  await dialog.getByRole("button", { name: "取消" }).click();

  await page.getByRole("button", { name: "拒绝", exact: true }).click();
  await dialog.getByRole("textbox", { name: "拒绝原因" }).fill("资料需要补充");
  await otherTab.getByRole("button", { name: "切换语言" }).click();
  await otherTab.getByRole("menuitem", { name: /English/ }).click();
  await expect(
    dialog.getByRole("heading", { name: "Reason for rejection" }),
  ).toBeVisible();
  await expect(
    dialog.getByRole("textbox", { name: "Reason for rejection" }),
  ).toHaveValue("资料需要补充");
  await otherTab.close();
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
        mfa_enabled: true,
        rows: [
          {
            id: "a",
            name: "设计协作",
            code: "design",
            description: "设计工具",
            status: "active",
            homepage_url: "https://design.example.test",
            logo_url: null,
            require_mfa: false,
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
  const submitted = page.waitForRequest(
    (r) =>
      r.method() === "POST" && r.url().endsWith("/account/applications/a/mfa"),
  );
  await page
    .getByRole("button", { name: "开启此应用的 MFA", exact: true })
    .click();
  expect(
    Object.fromEntries(new URLSearchParams((await submitted).postData()!)),
  ).toMatchObject({ action: "enable_mfa", csrf_token: "csrf-test" });
  await page.getByLabel("搜索应用").fill("finance");
  await expect(open).toHaveCount(0);
  await expect(page.getByText("暂无可用应用")).toBeVisible();
  await page.getByLabel("搜索应用").fill("DESIGN");
  await expect(open).toHaveCount(1);
});

test("permission assignment checks dependencies and submits explicit application grants", async ({
  page,
}) => {
  let revision = 2;
  const views = {
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
  };
  await mock(page, views);
  await page.route("**/dashboard/admins", (route) =>
    !route.request().headers().accept?.includes("application/json")
      ? route.fallback()
      : route.fulfill({
          json: {
            ...views["/dashboard/admins"],
            data: {
              ...views["/dashboard/admins"].data,
              rows: [
                {
                  ...views["/dashboard/admins"].data.rows[0],
                  grants: { revision, global_permissions: [], app_grants: {} },
                },
              ],
            },
          },
        }),
  );
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
  // Refreshing while editing must not submit an old draft with a new revision.
  revision = 3;
  const refreshed = page.waitForResponse(
    (r) => new URL(r.url()).pathname === "/dashboard/admins",
  );
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await refreshed;
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
  await page.route("**/dashboard/admins/users?q=*", async (route) => {
    expect(await route.request().headerValue("accept-language")).toBe("zh-CN");
    return route.fulfill({
      json: {
        users: [
          { id: "admin-1", username: "operator" },
          { id: "user-2", username: "alice" },
        ],
      },
    });
  });
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
  const clientId = page.getByRole("textbox", {
    name: "Client ID",
    exact: true,
  });
  const issuer = page.getByRole("textbox", { name: "Issuer", exact: true });
  const choose = async (name: string) => {
    await page
      .getByRole("combobox", { name: "服务商预设", exact: true })
      .click();
    await page.getByRole("option", { name, exact: true }).click();
  };
  await choose("Google");
  await expect(issuer).not.toBeVisible();
  await expect(clientId).toHaveAccessibleDescription(/服务商应用控制台/);
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
  await expect(issuer).toHaveValue("https://accounts.google.com");
  await clientId.fill("client-from-console");
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
  await expect(issuer).toHaveValue("");
  const tenantId = "11111111-2222-3333-4444-555555555555";
  await tenant.fill(tenantId);
  await expect(issuer).toHaveValue(
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
  await expect(issuer).toHaveCount(0);
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
  await expect(clientId).toHaveValue("client-from-console");
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
