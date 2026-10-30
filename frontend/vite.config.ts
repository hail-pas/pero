import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
export default defineConfig(({ command }) => ({
  base: command === "build" ? "/static/" : "/",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              name: "react",
              test: /node_modules\/(react|react-dom|react-router)(\/|$)/,
            },
            { name: "mui", test: /node_modules\/@mui\// },
          ],
        },
      },
    },
  },
  server: {
    port: 3039,
    proxy: Object.fromEntries(
      [
        "^/($|\\?)",
        "/static",
        "/account",
        "/dashboard",
        "/sso",
        "/oauth2",
        "/api",
        "/.well-known",
        "/login",
        "/callback",
        "/logout",
      ].map((path) => [
        path,
        {
          target: process.env.PERO_API_ORIGIN || "http://127.0.0.1:8080",
          bypass(req) {
            const pathname = new URL(req.url || "/", "http://localhost")
              .pathname;
            const page =
              [
                "/",
                "/login",
                "/account/security",
                "/account/reauth",
                "/sso/mfa",
                "/dashboard/admins",
                "/dashboard/registration",
                "/account/applications",
                "/sso/select-account",
                "/oauth2/authorize/access",
                "/account/login",
                "/account/profile",
                "/account/sessions",
                "/account/activity",
                "/account/authorizations",
                "/account/identities",
                "/dashboard/events",
                "/dashboard/audit",
                "/dashboard/notifications",
                "/account/change-password",
                "/account/profile/verify-contact",
                "/sso/login",
                "/sso/register",
                "/sso/forgot-password",
                "/sso/reset-password",
                "/sso/consent",
                "/sso/error",
                "/sso/social/link",
              ].includes(pathname) ||
              /^\/dashboard\/apps\/[^/]+\/(members|integration)$/.test(
                pathname,
              ) ||
              /^\/dashboard\/users\/[^/]+\/security$/.test(pathname) ||
              /^\/dashboard\/audit\/[^/]+$/.test(pathname) ||
              /^\/dashboard(?:\/(?:apps|users|providers)(?:\/[^/]+(?:\/edit)?)?)?$/.test(
                pathname,
              );
            if (
              req.method === "GET" &&
              page &&
              req.headers.accept?.includes("text/html")
            )
              return "/index.html";
          },
        },
      ]),
    ),
  },
}));
