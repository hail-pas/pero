import type { FormPreset } from "./forms";

// Public configuration only. Credentials and account policies remain user supplied.
const defaults = {
  issuer: "",
  jwks_uri: "",
  settings: "{}",
};

export const providerPresets: FormPreset[] = [
  {
    id: "google",
    label: "Google",
    documentationUrl:
      "https://developers.google.com/identity/openid-connect/openid-connect",
    values: {
      ...defaults,
      code: "google",
      name: "Google",
      kind: "oidc",
      icon: "google",
      issuer: "https://accounts.google.com",
      authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      token_endpoint: "https://oauth2.googleapis.com/token",
      userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
      jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
      scopes: "openid,profile,email",
    },
  },
  {
    id: "github",
    label: "GitHub",
    documentationUrl:
      "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps",
    values: {
      ...defaults,
      code: "github",
      name: "GitHub",
      kind: "oauth2",
      icon: "github",
      authorization_endpoint: "https://github.com/login/oauth/authorize",
      token_endpoint: "https://github.com/login/oauth/access_token",
      userinfo_endpoint: "https://api.github.com/user",
      scopes: "read:user,user:email",
      settings: JSON.stringify(
        { emails_endpoint: "https://api.github.com/user/emails" },
        null,
        2,
      ),
    },
  },
  {
    id: "gitlab",
    label: "GitLab.com",
    documentationUrl:
      "https://docs.gitlab.com/integration/openid_connect_provider/",
    values: {
      ...defaults,
      code: "gitlab",
      name: "GitLab",
      kind: "oidc",
      icon: "gitlab",
      issuer: "https://gitlab.com",
      authorization_endpoint: "https://gitlab.com/oauth/authorize",
      token_endpoint: "https://gitlab.com/oauth/token",
      userinfo_endpoint: "https://gitlab.com/oauth/userinfo",
      jwks_uri: "https://gitlab.com/oauth/discovery/keys",
      scopes: "openid,profile,email",
    },
  },
  {
    id: "microsoft",
    label: "Microsoft Entra ID",
    documentationUrl:
      "https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc",
    values: {
      ...defaults,
      code: "microsoft",
      name: "Microsoft",
      kind: "oidc",
      icon: "microsoft",
      authorization_endpoint: "",
      token_endpoint: "",
      userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo",
      scopes: "openid,profile,email",
    },
    parameter: {
      label: "目录（租户）ID",
      hint: "填写应用注册概述中的租户 ID（GUID），自动填充租户专属端点，填充后仍可修改。",
      pattern:
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
      values: (tenant) => {
        const authority = `https://login.microsoftonline.com/${tenant.toLowerCase()}`;
        return {
          issuer: tenant ? `${authority}/v2.0` : "",
          authorization_endpoint: tenant
            ? `${authority}/oauth2/v2.0/authorize`
            : "",
          token_endpoint: tenant ? `${authority}/oauth2/v2.0/token` : "",
          jwks_uri: tenant ? `${authority}/discovery/v2.0/keys` : "",
        };
      },
    },
  },
  {
    id: "wechat",
    label: "微信开放平台（网站扫码登录）",
    documentationUrl:
      "https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html",
    values: {
      ...defaults,
      code: "wechat",
      name: "微信",
      kind: "wechat",
      icon: "wechat",
      authorization_endpoint: "https://open.weixin.qq.com/connect/qrconnect",
      token_endpoint: "https://api.weixin.qq.com/sns/oauth2/access_token",
      userinfo_endpoint: "https://api.weixin.qq.com/sns/userinfo",
      scopes: "snsapi_login",
    },
  },
];
