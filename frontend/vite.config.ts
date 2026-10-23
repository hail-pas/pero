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
                "/account/login",
                "/account/profile",
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
