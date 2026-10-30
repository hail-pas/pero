import { expect, test } from "@playwright/test";

for (const action of ["retry", "other", "cancel"] as const) {
  test(`application access recovery submits ${action} with its bound request`, async ({
    page,
  }) => {
    await page.route("**/oauth2/authorize/access**", (route) => {
      if (!route.request().headers().accept?.includes("application/json"))
        return route.continue();
      return route.fulfill({
        json:
          route.request().method() === "POST"
            ? { code: 0 }
            : {
                view: "AppAccessDeniedView",
                data: {
                  csrf_token: "csrf-test",
                  token: "signed-recovery",
                  app_name: "测试应用",
                  username: "member",
                  system: false,
                  expired: false,
                },
              },
      });
    });
    await page.goto("/oauth2/authorize/access?token=signed-recovery");
    await expect(
      page.getByText("账号 member 尚无 测试应用 的访问资格。"),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "申请或查看访问资格" }),
    ).toHaveAttribute("href", "/account/applications");
    await expect(
      page.getByRole("link", { name: "申请或查看访问资格" }),
    ).toHaveAttribute("target", "_blank");
    const submitted = page.waitForRequest((r) => r.method() === "POST");
    await page
      .getByRole("button", {
        name: {
          retry: "已获得权限，重新尝试",
          other: "登录其他账号",
          cancel: "取消并返回个人中心",
        }[action],
      })
      .click();
    expect(
      Object.fromEntries(new URLSearchParams((await submitted).postData()!)),
    ).toEqual({ action, token: "signed-recovery", csrf_token: "csrf-test" });
  });
}

test("expired authorization explains how to restart and hides recovery actions", async ({
  page,
}) => {
  await page.route("**/oauth2/authorize/access**", (route) => {
    if (!route.request().headers().accept?.includes("application/json"))
      return route.continue();
    return route.fulfill({
      json: {
        view: "AppAccessDeniedView",
        data: {
          csrf_token: "csrf-test",
          token: "",
          app_name: "",
          username: "",
          system: false,
          expired: true,
        },
      },
    });
  });
  await page.goto("/oauth2/authorize/access?token=expired");
  await expect(page.getByText("授权请求已失效")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "已获得权限，重新尝试" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: "返回个人中心" }),
  ).toHaveAttribute("href", "/account/profile");
});
