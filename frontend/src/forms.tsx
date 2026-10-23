import { Visibility, VisibilityOff } from "@mui/icons-material";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  FormControlLabel,
  IconButton,
  InputAdornment,
  MenuItem,
  Stack,
  TextField,
} from "@mui/material";
import { useState, type FormEvent } from "react";
import type { Values } from "./api";
import { t, useLocale } from "./i18n";
export interface Field {
  name: string;
  label: string;
  type?: string;
  required?: boolean;
  disabled?: boolean;
  autoComplete?: string;
  options?: string[][];
  hint?: string;
  multiline?: boolean;
  default?: string | boolean | number;
}
export function FieldsForm({
  fields,
  initial = {},
  submit,
  label = t("保存更改"),
  footer,
  fullWidthSubmit = false,
}: {
  fields: Field[];
  initial?: Values;
  submit: (values: Values) => Promise<void>;
  label?: string;
  footer?: React.ReactNode;
  fullWidthSubmit?: boolean;
}) {
  useLocale();
  const [values, setValues] = useState<Values>(() =>
    Object.fromEntries(
      fields.map((f) => [
        f.name,
        f.options && !initial[f.name]
          ? (f.default ?? "")
          : Object.hasOwn(initial, f.name)
            ? f.type === "checkbox"
              ? Boolean(initial[f.name])
              : (initial[f.name] ?? "")
            : (f.default ?? (f.type === "checkbox" ? false : "")),
      ]),
    ),
  );
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [visible, setVisible] = useState<Record<string, boolean>>({});
  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await submit(values);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Box component="form" onSubmit={onSubmit}>
      <Stack spacing={2.5}>
        {error && (
          <Alert severity="error" role="alert">
            {t(error)}
          </Alert>
        )}
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: {
              xs: "1fr",
              sm: fields.length > 5 ? "1fr 1fr" : "1fr",
            },
            gap: 2.5,
          }}
        >
          {fields.map((f) =>
            f.type === "checkbox" ? (
              <FormControlLabel
                key={f.name}
                control={
                  <Checkbox
                    checked={Boolean(values[f.name])}
                    onChange={(e) =>
                      setValues({ ...values, [f.name]: e.target.checked })
                    }
                  />
                }
                label={t(f.label)}
              />
            ) : (
              <TextField
                key={f.name}
                name={f.name}
                label={t(f.label)}
                value={values[f.name] ?? ""}
                required={f.required}
                disabled={busy || f.disabled}
                fullWidth
                select={!!f.options}
                type={
                  f.type === "password" && visible[f.name]
                    ? "text"
                    : f.type || "text"
                }
                multiline={f.multiline}
                minRows={f.multiline ? 3 : undefined}
                helperText={t(f.hint)}
                autoComplete={
                  f.autoComplete ??
                  (f.type === "password"
                    ? f.name === "old_password"
                      ? "current-password"
                      : "new-password"
                    : f.name === "identifier"
                      ? "username"
                      : undefined)
                }
                onChange={(e) =>
                  setValues({ ...values, [f.name]: e.target.value })
                }
                sx={{ gridColumn: f.multiline ? "1 / -1" : undefined }}
                slotProps={
                  f.type === "password"
                    ? {
                        input: {
                          endAdornment: (
                            <InputAdornment position="end">
                              <IconButton
                                aria-label={
                                  visible[f.name]
                                    ? t("隐藏密码")
                                    : t("显示密码")
                                }
                                onClick={() =>
                                  setVisible({
                                    ...visible,
                                    [f.name]: !visible[f.name],
                                  })
                                }
                                edge="end"
                              >
                                <>
                                  {visible[f.name] ? (
                                    <VisibilityOff />
                                  ) : (
                                    <Visibility />
                                  )}
                                </>
                              </IconButton>
                            </InputAdornment>
                          ),
                        },
                      }
                    : undefined
                }
              >
                {f.options?.map(([value, title]) => (
                  <MenuItem key={value} value={value}>
                    {t(title)}
                  </MenuItem>
                ))}
              </TextField>
            ),
          )}
        </Box>
        {footer}
        <Box sx={{ display: "flex", justifyContent: "flex-end" }}>
          <Button
            type="submit"
            fullWidth={fullWidthSubmit}
            variant="contained"
            color="inherit"
            disabled={busy}
            size="large"
          >
            {busy ? t("正在提交…") : t(label)}
          </Button>
        </Box>
      </Stack>
    </Box>
  );
}
const text = (name: string, label: string, required = false): Field => ({
  name,
  label,
  required,
});
export const userFields: Field[] = [
  text("username", "用户名", true),
  text("nickname", "昵称"),
  { ...text("email", "邮箱"), type: "email" },
  text("phone", "手机号"),
  { ...text("avatar_url", "头像 URL"), type: "url" },
];
export const appFields: Field[] = [
  text("code", "应用标识", true),
  text("name", "应用名称", true),
  {
    name: "app_type",
    label: "应用类型",
    options: [
      ["web", "Web 应用"],
      ["spa", "单页应用"],
      ["mobile", "移动应用"],
      ["service", "服务端应用"],
    ],
    default: "web",
  },
  text("homepage_url", "应用主页"),
  text("logo_url", "Logo URL"),
  { name: "auto_access", label: "允许用户自动访问", type: "checkbox" },
  { ...text("description", "应用说明"), multiline: true },
];
export const providerFields: Field[] = [
  text("code", "提供方标识", true),
  text("name", "显示名称", true),
  {
    name: "kind",
    label: "协议类型",
    options: [
      ["oidc", "OpenID Connect"],
      ["oauth2", "OAuth 2.0"],
      ["wechat", "微信"],
      ["local", "本地账号"],
    ],
    default: "oidc",
  },
  text("icon", "图标"),
  text("issuer", "Issuer"),
  text("client_id", "Client ID"),
  {
    ...text("client_secret", "Client Secret"),
    type: "password",
    hint: "编辑时留空以保留现有密钥",
  },
  text("authorization_endpoint", "授权端点"),
  text("token_endpoint", "令牌端点"),
  text("userinfo_endpoint", "UserInfo 端点"),
  text("jwks_uri", "JWKS URI"),
  text("end_session_endpoint", "退出端点"),
  {
    ...text("scopes", "权限范围"),
    default: "openid,profile,email",
    hint: "使用英文逗号分隔",
  },
  { ...text("settings", "扩展配置 JSON"), multiline: true, default: "{}" },
  {
    name: "enabled",
    label: "启用此身份提供方",
    type: "checkbox",
    default: true,
  },
];
export const clientFields: Field[] = [
  text("identifier", "Client ID", true),
  text("name", "客户端名称"),
  {
    name: "client_type",
    label: "客户端类型",
    options: [
      ["confidential", "机密客户端"],
      ["public", "公开客户端"],
    ],
    default: "confidential",
  },
  {
    ...text("secret", "Client Secret"),
    type: "password",
    hint: "新建时留空则自动生成；编辑时留空则保留",
  },
  {
    ...text("redirect_uris", "回调地址", true),
    multiline: true,
    hint: "每行一个完整 URL",
  },
  {
    ...text("post_logout_redirect_uris", "退出回调地址"),
    multiline: true,
    hint: "每行一个完整 URL",
  },
  { ...text("scopes", "权限范围"), default: "openid,profile,email" },
  {
    ...text("grant_types", "授权类型"),
    default: "authorization_code,refresh_token",
  },
  { name: "require_pkce", label: "要求 PKCE", type: "checkbox", default: true },
  {
    name: "access_token_ttl",
    label: "Access Token 有效期（秒）",
    type: "number",
    default: 7200,
  },
  {
    name: "refresh_token_ttl",
    label: "Refresh Token 有效期（秒）",
    type: "number",
    default: 2592000,
  },
  {
    name: "id_token_ttl",
    label: "ID Token 有效期（秒）",
    type: "number",
    default: 7200,
  },
];
export const keyFields: Field[] = [
  text("kid", "Key ID", true),
  {
    name: "algorithm",
    label: "签名算法",
    options: ["RS256"].map((x) => [x, x]),
    default: "RS256",
  },
  { ...text("public_key_pem", "公钥 PEM", true), multiline: true },
  { ...text("private_key_pem", "私钥 PEM"), multiline: true },
  { ...text("certificate_pem", "证书 PEM"), multiline: true },
  {
    name: "not_before",
    label: "生效时间",
    hint: "RFC 3339，例如 2026-10-22T00:00:00Z",
  },
  { name: "expires_at", label: "过期时间", hint: "RFC 3339；可留空" },
  { name: "active", label: "立即激活", type: "checkbox" },
];
