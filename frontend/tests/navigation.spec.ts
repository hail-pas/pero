import { test, expect } from "@playwright/test";

for (const allowed of [true, false]) {
  test(`home and account navigation follow server entitlement: ${allowed}`, async ({
    page,
  }) => {
    let canAccess = allowed;
    let forbidden = false;
    const layout = () => ({
      user_name: "成员",
      user_username: "member",
      user_avatar_url: "",
      can_access_dashboard: canAccess,
    });
    await page.route("**/*", async (route) => {
      if (!route.request().headers().accept?.includes("application/json"))
        return route.continue();
      const path = new URL(route.request().url()).pathname;
      await route.fulfill({
        status: forbidden ? 403 : 200,
        json: forbidden
          ? { view: "ForbiddenView", data: { code: "forbidden" } }
          : path === "/"
            ? { view: "HomeView", data: { layout: layout() } }
            : {
                view: "SecurityView",
                data: {
                  layout: layout(),
                  csrf_token: "csrf",
                  providers: [],
                  codes: [],
                },
              },
      });
    });
    await page.goto("/");
    await expect(
      page.getByRole("link", { name: "管理控制台", exact: true }),
    ).toHaveCount(allowed ? 1 : 0);
    if (allowed)
      await expect(
        page.getByRole("link", { name: "管理控制台", exact: true }),
      ).toHaveAttribute("href", "/dashboard");
    await expect(
      page.getByRole("link", { name: "个人中心", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "登录", exact: true }),
    ).toHaveCount(0);
    await page.getByRole("link", { name: "个人中心", exact: true }).click();
    await expect(
      page.getByRole("link", { name: "管理控制台", exact: true }),
    ).toHaveCount(allowed ? 1 : 0);
    await page.getByRole("button", { name: "切换工作空间" }).last().click();
    await expect(
      page.getByRole("menuitem", { name: "管理工作空间" }),
    ).toHaveCount(allowed ? 1 : 0);
    await page.keyboard.press("Escape");

    // Returning to a tab must refresh role changes without a full page reload.
    canAccess = !allowed;
    await page.evaluate(() => window.dispatchEvent(new Event("focus")));
    await expect(
      page.getByRole("link", { name: "管理控制台", exact: true }),
    ).toHaveCount(canAccess ? 1 : 0);

    // A dashboard URL alone must never create administrator navigation.
    forbidden = true;
    await page.goto("/dashboard/apps");
    await expect(page.getByRole("alert")).toBeVisible();
    await expect(page.locator('a[href^="/dashboard"]')).toHaveCount(0);
  });
}

test("anonymous home has no dashboard entry", async ({ page }) => {
  await page.route("**/*", async (route) => {
    if (!route.request().headers().accept?.includes("application/json"))
      return route.continue();
    await route.fulfill({ json: { view: "HomeView", data: { layout: null } } });
  });
  await page.goto("/");
  await expect(
    page.getByRole("link", { name: "登录", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "注册账户", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "管理控制台", exact: true }),
  ).toHaveCount(0);
});

test("permission refresh preserves one-time MFA recovery codes", async ({
  page,
}) => {
  let requests = 0;
  await page.route("**/*", async (route) => {
    if (!route.request().headers().accept?.includes("application/json"))
      return route.continue();
    requests++;
    await route.fulfill({
      json: {
        view: "SecurityView",
        data: {
          layout: {
            user_name: "管理员",
            user_username: "admin",
            user_avatar_url: "",
            can_access_dashboard: true, admin_access: {super_admin:true,revision:0,global_permissions:[],app_grants:{}},
          },
          csrf_token: "csrf",
          codes: ["one-time-recovery-code"],
          redirect: "/account/profile",
        },
      },
    });
  });
  await page.goto("/account/security");
  await expect(page.getByText("one-time-recovery-code")).toBeVisible();
  const beforeFocus = requests;
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.getByText("one-time-recovery-code")).toBeVisible();
  expect(requests).toBe(beforeFocus);
});
