import { test, expect } from "@playwright/test";
import { createServer as createHttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { createServer as createViteServer } from "vite";

// Exercise the actual proxy: mocked browser routes cannot catch protocol bypasses.
test("development proxy executes a social callback once and keeps protocol requests on the backend", async ({
  page,
}) => {
  let callbacks = 0;
  const backend = createHttpServer((req, res) => {
    if (req.url?.startsWith("/sso/social/google/callback")) {
      callbacks++;
      res.writeHead(303, { Location: "/sso/error?code=callback_complete" });
      res.end();
    } else {
      res.setHeader("Content-Type", "application/json");
      res.end(
        JSON.stringify({
          view: "ErrorView",
          data: { code: "callback_complete" },
        }),
      );
    }
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
    await page.goto(
      `${origin}/sso/social/google/callback?code=single-use&state=nonce`,
    );
    await expect(page).toHaveURL(`${origin}/sso/error?code=callback_complete`);
    await expect(page.getByRole("alert")).toContainText("callback_complete");
    expect(callbacks).toBe(1);
    for (const pathname of [
      "/sso/social/google/login",
      "/api/providers",
      "/.well-known/openid-configuration",
      "/oauth2/authorize",
      "/callback",
    ]) {
      const response = await fetch(origin + pathname, {
        headers: { Accept: "text/html" },
      });
      expect(response.headers.get("content-type")).toContain(
        "application/json",
      );
    }
    const post = await fetch(`${origin}/account/profile`, {
      method: "POST",
      headers: { Accept: "text/html" },
    });
    expect(post.headers.get("content-type")).toContain("application/json");
  } finally {
    await vite.close();
    await new Promise<void>((resolve, reject) =>
      backend.close((error) => (error ? reject(error) : resolve())),
    );
    if (previousOrigin === undefined) delete process.env.PERO_API_ORIGIN;
    else process.env.PERO_API_ORIGIN = previousOrigin;
  }
});
