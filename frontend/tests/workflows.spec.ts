import { test, expect, type Page } from "@playwright/test";
const layout = { user_name: "成员", user_username: "member", is_admin: true };
const base = { layout, csrf_token: "csrf-test" };
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
