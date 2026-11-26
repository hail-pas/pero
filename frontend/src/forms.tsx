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
import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import type { Values } from "./api";
import { t, useLocale } from "./i18n";

export type FieldOptions = string[][];

export interface Field {
  name: string;
  label: string;
  type?: string;
  required?: boolean;
  disabled?: boolean;
  autoComplete?: string;
  /** Static options, or options derived from the current form values. */
  options?: FieldOptions | ((values: Values) => FieldOptions);
  hint?: string;
  multiline?: boolean;
  default?: string | boolean | number;
  advanced?: boolean;
  presetAdvanced?: boolean;
  /** Render the field only while the predicate matches the current values. */
  visibleWhen?: (values: Values) => boolean;
  /** A field can become required only in some modes. */
  requiredWhen?: (values: Values) => boolean;
  /** A field can be shown but read-only in some modes. */
  disabledWhen?: (values: Values) => boolean;
  /** Inline validation; return a translated message to block submission. */
  validate?: (value: Values[string], values: Values) => string | undefined;
  /** Groups related fields under a section label. */
  group?: string;
  /** Long values such as URLs or descriptions span the whole row. */
  span?: "full";
  placeholder?: string;
  min?: number;
  max?: number;
  step?: number;
  /** Non-input guidance rendered as an alert. */
  severity?: "info" | "success" | "warning";
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

function optionsOf(field: Field, values: Values) {
  if (!field.options) return [];
  return typeof field.options === "function"
    ? field.options(values)
    : field.options;
}

function isEmpty(value: Values[string]) {
  return value === undefined || value === null || String(value).trim() === "";
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
  submitColor = "primary",
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
  submitColor?: "primary" | "warning" | "error" | "inherit";
}) {
  useLocale();
  const formId = useId();
  const formRef = useRef<HTMLFormElement>(null);
  const [values, setValues] = useState<Values>(() =>
    Object.fromEntries(
      fields
        .filter((field) => field.type !== "notice")
        .map((f) => [
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
    [fieldErrors, setFieldErrors] = useState<Record<string, string>>({}),
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

  const visibleFields = useMemo(
    () => fields.filter((field) => !field.visibleWhen || field.visibleWhen(values)),
    [fields, values],
  );
  const isAdvanced = (field: Field) =>
    field.advanced || (selectedPreset && field.presetAdvanced);
  const mainFields = visibleFields.filter((field) => !isAdvanced(field));
  const advancedFields = visibleFields.filter(isAdvanced);

  const isRequired = (field: Field) =>
    field.requiredWhen ? field.requiredWhen(values) : Boolean(field.required);
  const isDisabled = (field: Field) =>
    busy || field.disabled || Boolean(field.disabledWhen?.(values));

  function validateField(field: Field) {
    if (field.type === "notice") return "";
    if (isRequired(field) && field.type !== "checkbox" && isEmpty(values[field.name]))
      return t("此字段为必填项");
    return field.validate?.(values[field.name], values) ?? "";
  }

  function clearFieldError(name: string) {
    setFieldErrors((current) => {
      if (!current[name]) return current;
      const next = { ...current };
      delete next[name];
      return next;
    });
  }

  function focusField(name: string) {
    window.requestAnimationFrame(() => {
      const element = formRef.current?.querySelector<HTMLElement>(
        `[name="${name}"]`,
      );
      element?.scrollIntoView({ block: "center", behavior: "smooth" });
      element?.focus({ preventScroll: true });
    });
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (submitting.current || disabled) return;
    const nextErrors: Record<string, string> = {};
    for (const field of visibleFields) {
      const message = validateField(field);
      if (message) nextErrors[field.name] = message;
    }
    setFieldErrors(nextErrors);
    const firstInvalid = Object.keys(nextErrors)[0];
    if (firstInvalid) {
      setError(nextErrors[firstInvalid]);
      focusField(firstInvalid);
      return;
    }
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

  function change(name: string, value: Values[string]) {
    setError("");
    clearFieldError(name);
    setValues((current) => ({ ...current, [name]: value }));
  }

  function renderField(f: Field) {
    if (f.type === "notice")
      return (
        <Alert
          key={f.name}
          severity={f.severity ?? "info"}
          sx={{ gridColumn: "1 / -1" }}
        >
          {t(f.label)}
          {f.hint && (
            <Typography variant="body2" sx={{ mt: 0.5 }}>
              {t(f.hint)}
            </Typography>
          )}
        </Alert>
      );
    const fieldError = fieldErrors[f.name];
    if (f.type === "checkbox")
      return (
        <Box key={f.name} sx={{ minWidth: 0 }}>
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
                disabled={isDisabled(f)}
                checked={Boolean(values[f.name])}
                onChange={(e) => change(f.name, e.target.checked)}
              />
            }
            label={t(f.label)}
          />
          {(f.hint || fieldError) && (
            <FormHelperText
              id={`${formId}-${f.name}-hint`}
              error={!!fieldError}
              sx={{ mx: 0 }}
            >
              {fieldError || t(f.hint)}
            </FormHelperText>
          )}
        </Box>
      );
    const options = optionsOf(f, values);
    return (
      <TextField
        key={f.name}
        size={compact ? "small" : undefined}
        name={f.name}
        label={t(f.label)}
        value={values[f.name] ?? ""}
        required={isRequired(f)}
        disabled={isDisabled(f)}
        fullWidth
        select={options.length > 0}
        type={
          f.type === "password" && visible[f.name] ? "text" : f.type || "text"
        }
        multiline={f.multiline}
        minRows={f.multiline ? 3 : undefined}
        error={!!fieldError}
        helperText={fieldError || t(f.hint)}
        placeholder={f.placeholder ? t(f.placeholder) : undefined}
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
        onChange={(e) => change(f.name, e.target.value)}
        onBlur={() => {
          const message = validateField(f);
          setFieldErrors((current) =>
            message
              ? { ...current, [f.name]: message }
              : Object.fromEntries(
                  Object.entries(current).filter(([key]) => key !== f.name),
                ),
          );
        }}
        sx={{
          gridColumn: f.span === "full" || f.multiline ? "1 / -1" : undefined,
        }}
        slotProps={{
          ...(f.type === "password"
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
                        {visible[f.name] ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                },
              }
            : {}),
          ...(f.type === "datetime-local" || f.type === "date"
            ? { inputLabel: { shrink: true } }
            : {}),
          ...(f.min !== undefined || f.max !== undefined || f.step !== undefined
            ? {
                htmlInput: {
                  min: f.min,
                  max: f.max,
                  step: f.step,
                },
              }
            : {}),
        }}
      >
        {options.map(([value, title]) => (
          <MenuItem key={value} value={value}>
            {t(title)}
          </MenuItem>
        ))}
      </TextField>
    );
  }

  function renderGrid(list: Field[]) {
    return (
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: compact
            ? {
                xs: "minmax(0, 1fr)",
                sm: "repeat(2, minmax(0, 1fr))",
                lg: "repeat(3, minmax(0, 1fr))",
              }
            : {
                xs: "minmax(0, 1fr)",
                sm:
                  list.length > 3
                    ? "repeat(2, minmax(0, 1fr))"
                    : "minmax(0, 1fr)",
              },
          gap: compact ? 2 : 2.5,
        }}
      >
        {list.map(renderField)}
      </Box>
    );
  }

  function renderGrouped(list: Field[]) {
    const groups: { name: string; fields: Field[] }[] = [];
    for (const field of list) {
      const name = field.group ?? "";
      let group = groups.find((item) => item.name === name);
      if (!group) {
        group = { name, fields: [] };
        groups.push(group);
      }
      group.fields.push(field);
    }
    return (
      <Stack spacing={2.5}>
        {groups.map((group, index) => (
          <Box key={group.name || index}>
            {group.name && (
              <Typography
                variant="overline"
                color="text.disabled"
                sx={{ display: "block", mb: 1, lineHeight: 1.8 }}
              >
                {t(group.name)}
              </Typography>
            )}
            {renderGrid(group.fields)}
          </Box>
        ))}
      </Stack>
    );
  }

  return (
    <Box component="form" ref={formRef} onSubmit={onSubmit} noValidate>
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
                setFieldErrors({});
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
        {mainFields.length > 0 && renderGrouped(mainFields)}
        {advancedFields.length > 0 && (
          <Accordion disableGutters elevation={0}>
            <AccordionSummary expandIcon={<ExpandMoreRounded />}>
              <Typography>{t("可选与高级配置")}</Typography>
            </AccordionSummary>
            <AccordionDetails>
              {renderGrouped(advancedFields)}
            </AccordionDetails>
          </Accordion>
        )}
        {footer}
        <Box
          sx={{
            display: "flex",
            flexDirection: fullWidthSubmit ? "column-reverse" : "row",
            justifyContent: fullWidthSubmit ? "stretch" : "flex-end",
            alignItems: "center",
            gap: 1,
            pt: 0.5,
          }}
        >
          {onCancel && (
            <Button
              disabled={busy}
              size={submitSize}
              onClick={onCancel}
              sx={fullWidthSubmit ? { width: "100%" } : undefined}
            >
              {t("取消")}
            </Button>
          )}
          <Button
            type="submit"
            fullWidth={fullWidthSubmit}
            variant="contained"
            color={submitColor}
            disabled={busy}
            size={submitSize}
            sx={fullWidthSubmit ? { width: "100%" } : { minWidth: { sm: 128 } }}
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
const positiveInteger = (value: Values[string]) => {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 && number <= 2147483647
    ? undefined
    : t("请输入有效的正整数");
};
const hasOpenid = (values: Values) =>
  String(values.scopes ?? "")
    .split(",")
    .map((scope) => scope.trim())
    .includes("openid");
const organizationMode = (values: Values) =>
  values.tenant_mode === "organization" || values.tenant_mode === "both";
export const userFields: Field[] = [
  { ...text("username", "用户名", true), group: "基本信息" },
  { ...text("nickname", "昵称"), group: "基本信息" },
  { ...text("email", "邮箱"), group: "联系方式", type: "email" },
  { ...text("phone", "手机号"), group: "联系方式" },
  { ...text("avatar_url", "头像 URL"), group: "基本信息", type: "url", span: "full" },
];
export const appFields: Field[] = [
  { ...text("code", "应用标识", true), group: "基本信息", hint: "用于生成回调地址和区分应用，创建后不可修改。" },
  { ...text("name", "应用名称", true), group: "基本信息" },
  { ...text("homepage_url", "应用主页"), group: "基本信息", span: "full" },
  { ...text("logo_url", "Logo URL"), group: "基本信息", span: "full" },
  { ...text("description", "应用说明"), group: "基本信息", multiline: true },
  {
    name: "session_limit_mode",
    label: "设备登录限制",
    group: "登录与访问",
    required: true,
    default: "limited",
    options: [
      ["unlimited", "关闭限制"],
      ["limited", "限制设备数量"],
    ],
    hint: "关闭限制后，同一账号可在任意数量设备上登录；限制模式会按应用维度保留最新会话。",
  },
  {
    name: "max_sessions",
    label: "最大登录设备数",
    group: "登录与访问",
    type: "number",
    required: true,
    default: 1,
    min: 1,
    step: 1,
    visibleWhen: (values) => values.session_limit_mode === "limited",
    requiredWhen: (values) => values.session_limit_mode === "limited",
    validate: positiveInteger,
    hint: "达到上限后，确认登录将退出最早的设备。减少额度会保留最新设备。",
  },
  {
    name: "tenant_mode",
    label: "租户模式",
    group: "登录与访问",
    required: true,
    options: [
      ["personal", "个人空间"],
      ["organization", "组织空间"],
      ["both", "个人及组织"],
    ],
    hint: "个人空间仅允许个人身份访问；组织空间仅限组织成员；个人及组织允许两种工作空间。选择后会展开组织准入设置。",
  },
  {
    name: "organization_access",
    label: "组织准入规则",
    group: "组织设置",
    required: true,
    options: [
      ["open", "所有符合条件的组织"],
      ["restricted", "仅明确授权的组织"],
    ],
    default: "open",
    visibleWhen: organizationMode,
    requiredWhen: organizationMode,
    hint: "仅控制组织是否能进入该应用，业务角色与数据权限仍由业务系统管理。",
  },
  {
    name: "organization_auto_access",
    label: "组织成员首次登录自动开通应用资格",
    group: "组织设置",
    type: "checkbox",
    default: false,
    visibleWhen: organizationMode,
    hint: "仅对有效组织成员生效；不会赋予个人空间访问资格。管理员明确撤销的用户仍需人工恢复。",
  },
];
const oidcOnly = (values: Values) => values.kind === "oidc";
const enabledProvider = (values: Values) => Boolean(values.enabled);
export const providerFields: Field[] = [
  {
    ...text("code", "提供方标识", true),
    group: "基本信息",
    hint: "用于区分登录渠道和生成回调地址，例如 google 或 microsoft；创建后不可修改。",
  },
  {
    ...text("name", "显示名称", true),
    group: "基本信息",
    hint: "用户在登录页看到的名称，例如“公司 Microsoft 账号”。",
  },
  {
    name: "kind",
    label: "协议类型",
    group: "基本信息",
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
    group: "协议配置",
    requiredWhen: enabledProvider,
    hint: "从服务商应用控制台复制应用 ID；微信对应 AppID。启用登录前必须填写。",
  },
  {
    ...text("client_secret", "Client Secret"),
    group: "协议配置",
    type: "password",
    hint: "从服务商应用控制台复制密钥，微信对应 AppSecret；是否必填以服务商要求为准，编辑时留空保留原密钥。",
  },
  {
    ...text("issuer", "Issuer"),
    group: "协议配置",
    visibleWhen: oidcOnly,
    requiredWhen: (values) => oidcOnly(values) && enabledProvider(values),
    presetAdvanced: true,
    hint: "OIDC 身份签发者的完整地址，须与服务商元数据中的 issuer 一致，启用 OIDC 时必填。",
  },
  {
    ...text("authorization_endpoint", "授权端点"),
    group: "协议配置",
    presetAdvanced: true,
    hint: "浏览器跳转到服务商登录和授权的地址；预设已填好，自定义接入请查阅服务商文档。",
  },
  {
    ...text("token_endpoint", "令牌端点"),
    group: "协议配置",
    presetAdvanced: true,
    hint: "服务器用授权码换取令牌的地址，由服务商提供。",
  },
  {
    ...text("userinfo_endpoint", "UserInfo 端点"),
    group: "协议配置",
    requiredWhen: enabledProvider,
    presetAdvanced: true,
    hint: "获取登录用户身份和资料的接口地址，启用登录前必须填写。",
  },
  {
    ...text("jwks_uri", "JWKS URI"),
    group: "协议配置",
    visibleWhen: oidcOnly,
    presetAdvanced: true,
    hint: "服务商公布 ID Token 验签公钥的地址，仅 OIDC 需要，启用 OIDC 时必填。",
  },
  {
    ...text("scopes", "权限范围"),
    group: "协议配置",
    default: "openid,profile,email",
    presetAdvanced: true,
    hint: "申请读取的用户资料权限，以英文逗号分隔。OIDC 必须包含 openid，微信网站扫码登录使用 snsapi_login。",
  },
  {
    name: "allow_registration",
    label: "允许此身份源参与注册",
    group: "账户策略",
    type: "checkbox",
    hint: "允许新用户通过此渠道注册，仍受系统和应用注册策略限制；关闭后仅供已有账号登录或绑定。",
  },
  {
    name: "enabled",
    label: "启用此身份提供方",
    group: "账户策略",
    type: "checkbox",
    default: true,
    hint: "开启后会出现在登录页；暂未填齐配置时可关闭，先保存为草稿。",
  },
  {
    ...text("icon", "图标"),
    group: "高级选项",
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
    group: "高级选项",
    multiline: true,
    default: "{}",
    advanced: true,
    visibleWhen: (values) => values.kind !== "wechat",
    hint: "可选，通常保留 {}。例如 GitHub 可设置 emails_endpoint 获取邮箱；预设已包含所需配置。",
  },
];
export const clientFields: Field[] = [
  { ...text("login_uri", "Login URI"), group: "基本信息", span: "full" },
  { ...text("identifier", "Client ID", true), group: "基本信息" },
  { ...text("name", "客户端名称"), group: "基本信息" },
  {
    name: "client_type",
    label: "客户端类型",
    group: "基本信息",
    options: [
      ["confidential", "机密客户端"],
      ["public", "公开客户端"],
    ],
    default: "confidential",
    hint: "机密客户端由服务端保管密钥；公开客户端（SPA、移动应用）不使用密钥，必须配合 PKCE。",
  },
  {
    ...text("secret", "Client Secret"),
    group: "授权配置",
    type: "password",
    visibleWhen: (values) => values.client_type !== "public",
    hint: "新建时留空则自动生成；编辑时留空则保留",
  },
  {
    ...text("redirect_uris", "回调地址", true),
    group: "授权配置",
    multiline: true,
    span: "full",
    hint: "每行一个完整 URI。公开客户端可将自己控制的域名倒写为私有 Scheme，例如 com.example.app:/callback。",
  },
  {
    ...text("post_logout_redirect_uris", "退出回调地址"),
    group: "授权配置",
    multiline: true,
    span: "full",
    hint: "每行一个完整 URI。公开客户端可将自己控制的域名倒写为私有 Scheme，例如 com.example.app:/callback。",
  },
  { ...text("scopes", "权限范围"), group: "授权配置", default: "openid,profile,email" },
  {
    ...text("grant_types", "授权类型"),
    group: "授权配置",
    default: "authorization_code,refresh_token",
  },
  {
    name: "require_pkce",
    label: "要求 PKCE",
    group: "授权配置",
    type: "checkbox",
    default: true,
  },
  {
    name: "access_token_ttl",
    label: "Access Token 有效期（秒）",
    group: "令牌有效期",
    type: "number",
    default: 7200,
    min: 1,
    step: 1,
    validate: positiveInteger,
  },
  {
    name: "refresh_token_ttl",
    label: "Refresh Token 有效期（秒）",
    group: "令牌有效期",
    type: "number",
    default: 2592000,
    min: 1,
    step: 1,
    validate: positiveInteger,
  },
  {
    name: "id_token_ttl",
    label: "ID Token 有效期（秒）",
    group: "令牌有效期",
    type: "number",
    default: 7200,
    min: 1,
    step: 1,
    validate: positiveInteger,
    visibleWhen: hasOpenid,
    hint: "仅在权限范围包含 openid 时签发 ID Token。",
  },
];
export const keyFields: Field[] = [
  { ...text("kid", "Key ID", true), group: "密钥信息" },
  {
    name: "algorithm",
    label: "签名算法",
    group: "密钥信息",
    options: ["RS256"].map((x) => [x, x]),
    default: "RS256",
  },
  {
    ...text("public_key_pem", "公钥 PEM", true),
    group: "密钥材料",
    multiline: true,
    span: "full",
  },
  {
    ...text("private_key_pem", "私钥 PEM"),
    group: "密钥材料",
    multiline: true,
    span: "full",
  },
  {
    ...text("certificate_pem", "证书 PEM"),
    group: "密钥材料",
    multiline: true,
    span: "full",
  },
  {
    name: "not_before",
    label: "生效时间",
    group: "有效期与状态",
    hint: "RFC 3339，例如 2026-10-22T00:00:00Z",
  },
  {
    name: "expires_at",
    label: "过期时间",
    group: "有效期与状态",
    hint: "RFC 3339；可留空",
  },
  {
    name: "active",
    label: "立即激活",
    group: "有效期与状态",
    type: "checkbox",
  },
];
