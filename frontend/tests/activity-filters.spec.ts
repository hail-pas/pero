import { test, expect } from "@playwright/test";

test.use({ timezoneId: "Asia/Shanghai" });

test("activity queries refresh rows and preserve combined filters", async ({
  page,
}) => {
  const events = [
    {
      id: "recent",
      username: "admin",
      event_type: "login_success",
      ip: "127.0.0.1",
      created_at: "2026-10-30T06:15:50Z",
    },
    {
      id: "older",
      username: "admin",
      event_type: "logout",
      ip: "127.0.0.1",
      created_at: "2026-10-30T04:55:51Z",
    },
    {
      id: "other",
      username: "member",
      event_type: "login_failure",
      ip: "192.0.2.1",
      created_at: "2026-10-29T04:00:00Z",
    },
  ];
  await page.route(/\/dashboard\/events(?:\?|$)/, async (route) => {
    if (!route.request().headers().accept?.includes("application/json"))
      return route.continue();
    const params = new URL(route.request().url()).searchParams;
    const { q, ip, from, to, event_type } = Object.fromEntries(params);
    const rows = events.filter(
      (event) =>
        (!q || event.username.includes(q)) &&
        (!ip || event.ip === ip) &&
        (!from || Date.parse(event.created_at) >= Date.parse(from)) &&
        (!to || Date.parse(event.created_at) <= Date.parse(to)) &&
        (!event_type || event.event_type === event_type),
    );
    await route.fulfill({
      json: {
        view: "ActivityListView",
        data: {
          layout: {
            user_name: "admin",
            user_username: "admin",
            can_access_dashboard: true,
            admin_access: {
              super_admin: true,
              revision: 0,
              global_permissions: [],
              app_grants: {},
            },
          },
          csrf_token: "csrf-test",
          rows,
          page: Number(params.get("page") || 1),
          total_pages: 1,
        },
      },
    });
  });
  await page.goto("/dashboard/events?page=2");
  const rows = page.locator("tbody tr");
  await expect(rows).toHaveCount(3);
  await page.getByLabel("用户名", { exact: true }).fill("admin");
  await page.getByLabel("IP 地址", { exact: true }).fill("127.0.0.1");
  await page.getByLabel("开始时间", { exact: true }).fill("2026-10-30T12:00");
  await page.getByLabel("结束时间", { exact: true }).fill("2026-10-30T13:00");
  await page.getByRole("button", { name: "查询", exact: true }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows).toContainText("退出登录");
  await page.getByLabel("事件类型", { exact: true }).click();
  await page.getByRole("option", { name: "登录成功", exact: true }).click();
  await expect(page.getByText("暂无记录。", { exact: true })).toBeVisible();
  expect(Object.fromEntries(new URL(page.url()).searchParams)).toEqual({
    q: "admin",
    ip: "127.0.0.1",
    from: "2026-10-30T04:00:00.000Z",
    to: "2026-10-30T05:00:00.000Z",
    event_type: "login_success",
  });
});
