import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests",
  timeout: 60000,
  fullyParallel: true,
  use: { baseURL: "http://127.0.0.1:3039", headless: true, locale: "zh-CN" },
  webServer: {
    command: "pnpm dev",
    url: "http://127.0.0.1:3039/index.html",
    reuseExistingServer: !process.env.CI,
  },
  reporter: "list",
});
