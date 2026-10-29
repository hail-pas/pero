import {
  ExpandMoreRounded,
  Visibility,
  VisibilityOff,
} from "@mui/icons-material";
import {
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  FormHelperText,
  Typography,
  Box,
  Button,
  Checkbox,
  FormControlLabel,
  IconButton,
  InputAdornment,
  MenuItem,
  Link,
  Stack,
  TextField,
} from "@mui/material";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";
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
  advanced?: boolean;
  presetAdvanced?: boolean;
  visibleWhen?: (values: Values) => boolean;
}
export interface FormPreset {
  id: string;
  label: string;
  values: Values;
  documentationUrl: string;
  parameter?: {
    label: string;
    hint: string;
    pattern: string;
    values: (input: string) => Values;
  };
}
export function FieldsForm({
  fields,
  compact = false,
  presets,
  initial = {},
  submit,
  label = t("保存更改"),
  footer,
  fullWidthSubmit = false,
  onBusyChange,
  submitSize = "large",
  onCancel,
  serverError = "",
  disabled = false,
}: {
  fields: Field[];
  compact?: boolean;
  presets?: FormPreset[];
  initial?: Values;
  submit: (values: Values) => Promise<void>;
  label?: string;
  footer?: React.ReactNode;
  fullWidthSubmit?: boolean;
  onBusyChange?: (busy: boolean) => void;
  submitSize?: "small" | "medium" | "large";
  onCancel?: () => void;
  serverError?: string;
  disabled?: boolean;
}) {
  useLocale();
  const formId = useId();
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
  const [presetId, setPresetId] = useState("");
  const [presetParameter, setPresetParameter] = useState("");
  const selectedPreset = presets?.find((preset) => preset.id === presetId);
  const [submittingState, setBusy] = useState(false),
    [error, setError] = useState(serverError),
    [visible, setVisible] = useState<Record<string, boolean>>({});
  const busy = submittingState || disabled;
  const submitting = useRef(false);
  const errorRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    setError(serverError);
  }, [serverError]);
  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);
  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (submitting.current || disabled) return;
    submitting.current = true;
    setBusy(true);
    onBusyChange?.(true);
    setError("");
    try {
      await submit(values);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      submitting.current = false;
      setBusy(false);
      onBusyChange?.(false);
    }
  }
  const visibleFields = fields.filter(
    (field) => !field.visibleWhen || field.visibleWhen(values),
  );
  const isAdvanced = (field: Field) =>
    field.advanced || (selectedPreset && field.presetAdvanced);
  const mainFields = visibleFields.filter((field) => !isAdvanced(field));
  const advancedFields = visibleFields.filter(isAdvanced);
  const renderFields = (list: Field[]) => (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: {
          xs: "minmax(0, 1fr)",
          sm:
            compact || list.length > 5
              ? "repeat(2, minmax(0, 1fr))"
              : "minmax(0, 1fr)",
          lg: compact ? "repeat(3, minmax(0, 1fr))" : undefined,
        },
        gap: compact ? 2 : 2.5,
      }}
    >
      {list.map((f) =>
        f.type === "checkbox" ? (
          <Box key={f.name}>
            <FormControlLabel
              control={
                <Checkbox
                  name={f.name}
                  slotProps={{
                    input: {
                      "aria-describedby": f.hint
                        ? `${formId}-${f.name}-hint`
                        : undefined,
                    },
                  }}
                  disabled={busy || f.disabled}
                  checked={Boolean(values[f.name])}
                  onChange={(e) => {
                    setError("");
                    setValues({ ...values, [f.name]: e.target.checked });
                  }}
                />
              }
              label={t(f.label)}
            />
            {f.hint && (
              <FormHelperText id={`${formId}-${f.name}-hint`} sx={{ mx: 0 }}>
                {t(f.hint)}
              </FormHelperText>
            )}
          </Box>
        ) : (
          <TextField
            key={f.name}
            size={compact ? "small" : undefined}
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
            onChange={(e) => {
              setError("");
              setValues({ ...values, [f.name]: e.target.value });
            }}
            sx={{ gridColumn: f.multiline ? "1 / -1" : undefined }}
            slotProps={
              f.type === "password"
                ? {
                    input: {
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton
                            disabled={busy}
                            aria-label={
                              visible[f.name] ? t("隐藏密码") : t("显示密码")
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
                : f.type === "datetime-local" || f.type === "date"
                  ? { inputLabel: { shrink: true } }
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
  );
  return (
    <Box component="form" onSubmit={onSubmit}>
      <Stack spacing={2.5}>
        {error && (
          <Alert ref={errorRef} tabIndex={-1} severity="error" role="alert">
            {t(error)}
          </Alert>
        )}
        {presets && (
          <Stack spacing={1} sx={{ maxWidth: 480 }}>
            <TextField
              select
              size="small"
              label={t("服务商预设")}
              value={presetId}
              disabled={busy}
              helperText={t(
                "自动填充公共配置，所有字段仍可修改。切换预设保留已填的 Client ID、密钥和账户策略。",
              )}
              onChange={(event) => {
                const id = event.target.value;
                setPresetId(id);
                setPresetParameter("");
                setError("");
                const preset = presets.find((preset) => preset.id === id);
                if (preset)
                  setValues((current) => ({ ...current, ...preset.values }));
              }}
            >
              <MenuItem value="">{t("自定义配置")}</MenuItem>
              {presets.map((preset) => (
                <MenuItem key={preset.id} value={preset.id}>
                  {t(preset.label)}
                </MenuItem>
              ))}
            </TextField>
            {selectedPreset?.parameter && (
              <TextField
                size="small"
                label={t(selectedPreset.parameter.label)}
                helperText={t(selectedPreset.parameter.hint)}
                required
                disabled={busy}
                value={presetParameter}
                slotProps={{
                  htmlInput: { pattern: selectedPreset.parameter.pattern },
                }}
                onChange={(event) => {
                  const input = event.target.value.trim();
                  setPresetParameter(input);
                  setError("");
                  const parameter = selectedPreset.parameter!;
                  const valid = new RegExp(`^(?:${parameter.pattern})$`).test(
                    input,
                  );
                  setValues((current) => ({
                    ...current,
                    ...parameter.values(valid ? input : ""),
                  }));
                }}
              />
            )}
            {selectedPreset && (
              <Link
                href={selectedPreset.documentationUrl}
                target="_blank"
                rel="noopener noreferrer"
                variant="body2"
              >
                {t("查看服务商接入文档")}
              </Link>
            )}
          </Stack>
        )}
        {mainFields.length > 0 && renderFields(mainFields)}
        {advancedFields.length > 0 && (
          <Accordion
            disableGutters
            elevation={0}
            sx={{
              border: 1,
              borderColor: "divider",
              borderRadius: 1,
              "&:before": { display: "none" },
            }}
          >
            <AccordionSummary expandIcon={<ExpandMoreRounded />}>
              <Typography>{t("可选与高级配置")}</Typography>
            </AccordionSummary>
            <AccordionDetails>{renderFields(advancedFields)}</AccordionDetails>
          </Accordion>
        )}
        {footer}
        <Box
          sx={{
            display: "flex",
            justifyContent: "flex-end",
            alignItems: "center",
            gap: 1,
          }}
        >
          {onCancel && (
            <Button disabled={busy} size={submitSize} onClick={onCancel}>
              {t("取消")}
            </Button>
          )}
          <Button
            type="submit"
            fullWidth={fullWidthSubmit}
            variant="contained"
            color="inherit"
            disabled={busy}
            size={submitSize}
          >
            {submittingState ? t("正在提交…") : t(label)}
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
  { ...text("description", "应用说明"), multiline: true },
];
const oidcOnly = (values: Values) => values.kind === "oidc";
export const providerFields: Field[] = [
  {
    ...text("code", "提供方标识", true),
    hint: "用于区分登录渠道和生成回调地址，例如 google 或 microsoft；创建后不可修改。",
  },
  {
    ...text("name", "显示名称", true),
    hint: "用户在登录页看到的名称，例如“公司 Microsoft 账号”。",
  },
  {
    name: "kind",
    label: "协议类型",
    presetAdvanced: true,
    options: [
      ["oidc", "OpenID Connect"],
      ["oauth2", "OAuth 2.0"],
      ["wechat", "微信"],
    ],
    default: "oidc",
    hint: "按服务商接入文档选择；使用预设时已自动选好，创建后不可修改。",
  },
  {
    ...text("client_id", "Client ID"),
    hint: "从服务商应用控制台复制应用 ID；微信对应 AppID。启用登录前必须填写。",
  },
  {
    ...text("client_secret", "Client Secret"),
    type: "password",
    hint: "从服务商应用控制台复制密钥，微信对应 AppSecret；是否必填以服务商要求为准，编辑时留空保留原密钥。",
  },
  {
    ...text("issuer", "Issuer"),
    visibleWhen: oidcOnly,
    presetAdvanced: true,
    hint: "OIDC 身份签发者的完整地址，须与服务商元数据中的 issuer 一致，启用 OIDC 时必填。",
  },
  {
    ...text("authorization_endpoint", "授权端点"),
    presetAdvanced: true,
    hint: "浏览器跳转到服务商登录和授权的地址；预设已填好，自定义接入请查阅服务商文档。",
  },
  {
    ...text("token_endpoint", "令牌端点"),
    presetAdvanced: true,
    hint: "服务器用授权码换取令牌的地址，由服务商提供。",
  },
  {
    ...text("userinfo_endpoint", "UserInfo 端点"),
    presetAdvanced: true,
    hint: "获取登录用户身份和资料的接口地址，启用登录前必须填写。",
  },
  {
    ...text("jwks_uri", "JWKS URI"),
    visibleWhen: oidcOnly,
    presetAdvanced: true,
    hint: "服务商公布 ID Token 验签公钥的地址，仅 OIDC 需要，启用 OIDC 时必填。",
  },
  {
    ...text("scopes", "权限范围"),
    default: "openid,profile,email",
    presetAdvanced: true,
    hint: "申请读取的用户资料权限，以英文逗号分隔。OIDC 必须包含 openid，微信网站扫码登录使用 snsapi_login。",
  },
  {
    name: "allow_registration",
    label: "允许此身份源参与注册",
    type: "checkbox",
    hint: "允许新用户通过此渠道注册，仍受系统和应用注册策略限制；关闭后仅供已有账号登录或绑定。",
  },
  {
    name: "enabled",
    label: "启用此身份提供方",
    type: "checkbox",
    default: true,
    hint: "开启后会出现在登录页；暂未填齐配置时可关闭，先保存为草稿。",
  },
  {
    ...text("icon", "图标"),
    advanced: true,
    options: [
      ["", "默认图标"],
      ...[
        "google",
        "github",
        "gitlab",
        "microsoft",
        "wechat",
        "oidc",
        "oauth2",
      ].map((icon) => [icon, icon]),
    ],
    hint: "可选，登录按钮使用的图标；留空使用协议默认图标。",
  },
  {
    ...text("settings", "扩展配置 JSON"),
    multiline: true,
    default: "{}",
    advanced: true,
    visibleWhen: (values) => values.kind !== "wechat",
    hint: "可选，通常保留 {}。例如 GitHub 可设置 emails_endpoint 获取邮箱；预设已包含所需配置。",
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
