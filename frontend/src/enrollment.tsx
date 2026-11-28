import { useAction } from "./use-action";
import { can } from "./permissions";
import { useState } from "react";
import {
  Alert,
  Button,
  Stack,
  Typography,
  Pagination,
  Avatar,
  TextField,
  Box,
  Container,
} from "@mui/material";
import { Link as RouterLink, useSearchParams } from "react-router-dom";
import {
  FieldsForm,
  invitationExceptionFields,
  invitationFields,
  invitationValues,
  type Field,
} from "./forms";
import { Heading, Panel, type Actions } from "./shared";
import { date, errorText, type Values } from "./api";
import type { ProgressList, ViewDataMap } from "./contracts";
import { labelValue, t, useLocale } from "./i18n";
import { LanguageSwitcher } from "./language-switcher";

const emailField: Field = {
  name: "email",
  label: "邮箱",
  type: "email",
  autoComplete: "email",
};
const phoneField: Field = {
  name: "phone",
  label: "手机号",
  type: "tel",
  autoComplete: "tel",
  hint: "请填写国际区号，例如 +8613800000000。",
  validate: (value) => {
    const phone = String(value ?? "").trim();
    if (phone && !/^\+[0-9]{7,15}$/.test(phone))
      return () => errorText("invalid_phone");
  },
};
const usernameField: Field = {
  name: "username",
  label: "用户名",
  required: true,
  autoComplete: "username",
  hint: "使用 3–64 个字符，可包含英文字母、数字、下划线和连字符。",
  validate: (value) => {
    const username = String(value ?? "").trim();
    if (/[^a-zA-Z0-9_-]/.test(username))
      return () => errorText("username_chars_invalid");
    if (username.length < 3 || username.length > 64)
      return () => errorText("username_length_invalid");
  },
};

function admissionStatus(status: string) {
  const labels: Record<string, string> = {
    pending_verification: t("待验证联系方式"),
    pending_approval: t("待审批"),
    ready: t("待完成"),
    completed: t("已完成"),
    rejected: t("已拒绝"),
    revoked: t("已撤销"),
    expired: t("已过期"),
    active: t("可访问"),
    disabled: t("已停用"),
  };
  return labels[status] || t("未知状态");
}

export function Enrollment({
  data,
  mutate,
}: {
  data: ViewDataMap["EnrollmentView"];
  mutate: Actions["mutate"];
}) {
  const { locale } = useLocale();
  const { error: failure, busy, run, clearError } = useAction();
  const [formBusy, setFormBusy] = useState(false);
  const [preferredChannel, setChannel] = useState<"phone" | "email">("email");
  const submit = (values: Values) =>
    mutate("/sso/register", { ...values, flow: data.flow });
  const perform = (action: string) => run(() => submit({ action }));
  const completed = data.status === "completed";
  const terminal = ["completed", "rejected", "revoked", "expired"].includes(
    data.status,
  );
  const blocked = data.mode === "closed" || data.status === "blocked";
  const hasFlow = Boolean(data.status || data.app || data.tenant_invitation);
  const canAct = data.can_act !== false;
  const contact = data.phone || data.email;
  const loginQuery = `redirect=%2Fsso%2Fregister&flow=${encodeURIComponent(data.flow)}`;
  const loginHref = `/sso/register/login?${loginQuery}`;
  const methods = (data.allowed_methods ?? ["email", "phone"]).filter(
    (method) => !data.social || method === "email",
  );
  const channel = methods.includes(preferredChannel)
    ? preferredChannel
    : methods.includes("phone")
      ? "phone"
      : "email";
  const socialProviders = (data.providers ?? []).map((p) => (
    <Button
      key={p.key}
      component="a"
      href={`/sso/social/${encodeURIComponent(p.key)}/login?${loginQuery}`}
      disabled={busy || formBusy}
      variant="outlined"
    >
      {p.name}
    </Button>
  ));
  const policy = data.password_policy;
  const passwordRequirements = policy
    ? [
        policy.require_uppercase && t("大写字母"),
        policy.require_lowercase && t("小写字母"),
        policy.require_digit && t("数字"),
        policy.require_special && t("特殊字符"),
      ].filter((requirement) => typeof requirement === "string")
    : [];
  const passwordHint = policy
    ? [
        t("密码长度为 {{min}}–{{max}} 个字符。", {
          min: policy.min_length,
          max: policy.max_length,
        }),
        passwordRequirements.length > 0 &&
          t("密码需包含{{requirements}}。", {
            requirements: new Intl.ListFormat(locale).format(
              passwordRequirements,
            ),
          }),
      ]
        .filter(Boolean)
        .join(" ")
    : undefined;
  function onFormBusyChange(submitting: boolean) {
    setFormBusy(submitting);
    if (submitting) clearError();
  }
  const registrationForm = (
    <FieldsForm
      disabled={busy}
      onBusyChange={onFormBusyChange}
      fields={[
        usernameField,
        ...(!data.social
          ? [
              {
                name: "password",
                label: "密码",
                type: "password",
                required: true,
                hint: passwordHint,
              },
            ]
          : []),
        ...(data.account_invitation
          ? [emailField, phoneField].filter((field) =>
              methods.includes(field.name),
            )
          : []),
      ]}
      submit={(values) => submit({ ...values, action: "finalize" })}
      label={data.tenant_invitation ? t("创建账号并加入组织") : t("创建账号")}
    />
  );
  const approvalNotice = data.phone
    ? t("手机号已验证，等待管理员审批。审批结果将通过短信发送。")
    : t("邮箱已验证，等待管理员审批。审批结果将通过邮件发送。");
  const socialNotice = data.social && (
    <Alert severity="info">
      {t(
        "第三方登录验证有效期为 10 分钟。到期或换设备后，请通过原身份源重新登录。",
      )}
    </Alert>
  );
  let description: string | undefined;
  if (data.account_invitation) {
    if (
      methods.length > 0 &&
      data.status === "ready" &&
      canAct &&
      !data.signed_in &&
      !blocked
    )
      description = t(
        "联系方式为选填项。填写后会收到验证码，开户后可前往个人中心完成验证。",
      );
  } else if (data.tenant_invitation) {
    description = data.tenant_name;
  } else if (data.social && !data.status && methods.includes("email")) {
    description = t("请填写邮箱，并打开验证邮件中的链接继续第三方账号注册。");
  } else if (data.app && !terminal && !blocked) {
    description = t("完成此应用的准入要求后获得访问资格。");
  } else if (!data.status && !blocked && data.mode !== "invite_only") {
    if (methods.length === 2) description = t("验证手机或邮箱并完成账户注册。");
    else if (methods.includes("email"))
      description = t("验证邮箱并完成账户注册。");
    else if (methods.includes("phone"))
      description = t("验证手机号并完成账户注册。");
  }
  return (
    <Container
      component="main"
      maxWidth="sm"
      sx={{
        minHeight: "100dvh",
        px: { xs: 2, sm: 3 },
        py: { xs: 4, sm: 6, md: 8 },
      }}
    >
      <Stack direction="row" sx={{ justifyContent: "space-between", mb: 3 }}>
        {!hasFlow && (
          <Button component={RouterLink} to="/sso/login">
            {t("返回登录")}
          </Button>
        )}
        <Box sx={{ ml: "auto" }}>
          <LanguageSwitcher />
        </Box>
      </Stack>
      {(failure || data.error) && (
        <Alert
          severity={
            data.error === "enrollment_completed_login_required"
              ? "info"
              : "error"
          }
          sx={{ mb: 3 }}
        >
          {failure || errorText(data.error || "")}
        </Alert>
      )}
      <Heading title={t("注册与应用准入")} description={description} />
      <Panel title={t("注册进度")}>
        {data.app_name && (
          <Typography sx={{ mb: 2 }}>
            {labelValue("注册应用", data.app_name)}
          </Typography>
        )}
        {terminal ? (
          <Stack spacing={2}>
            <Alert severity={completed ? "success" : "info"}>
              {admissionStatus(data.status)}
            </Alert>
            {data.reason && <Typography>{data.reason}</Typography>}
            {completed &&
              (data.matching_account ? (
                <Button disabled={busy} onClick={() => perform("continue")}>
                  {t("继续")}
                </Button>
              ) : data.signed_in ? (
                <Button disabled={busy} onClick={() => perform("switch")}>
                  {t("登录已有账户")}
                </Button>
              ) : (
                <Button component={RouterLink} to={loginHref}>
                  {t("登录后继续")}
                </Button>
              ))}
          </Stack>
        ) : blocked ? (
          <Stack spacing={2}>
            {!data.error && <Alert severity="info">{t("注册已关闭")}</Alert>}
          </Stack>
        ) : data.status && !canAct ? (
          <Stack spacing={2}>
            {contact && <Typography>{contact}</Typography>}
            <Alert severity="info">
              {data.manual_delivery
                ? t("请联系发出邀请的管理员，获取最新的邀请链接。")
                : data.status === "pending_verification"
                  ? t(
                      data.phone
                        ? "验证短信已排队，请打开短信中的链接继续。"
                        : "验证邮件已排队，请打开邮件中的链接继续。",
                    )
                  : data.status === "pending_approval"
                    ? approvalNotice
                    : admissionStatus(data.status)}
              {data.status === "ready" && !data.manual_delivery && (
                <Typography>{t("请打开最新的通知链接继续办理。")}</Typography>
              )}
            </Alert>
            {data.expires_at && (
              <Typography variant="body2">
                {t("到期时间")} {date(data.expires_at)}
              </Typography>
            )}
          </Stack>
        ) : data.tenant_invitation ||
          (data.existing_account &&
            (data.status === "ready" || data.status === "pending_approval")) ? (
          <Stack spacing={2}>
            {(data.tenant_name || contact) && (
              <Typography>
                {[data.tenant_name, contact].filter(Boolean).join(" · ")}
              </Typography>
            )}
            {data.already_admitted && (
              <Alert severity="info">
                {t(
                  data.tenant_invitation
                    ? "你已在此组织"
                    : data.app
                      ? "你已拥有此应用的访问资格"
                      : "你已有账户",
                )}
              </Alert>
            )}
            {data.matching_account ? (
              <Button
                variant="contained"
                disabled={busy || formBusy}
                onClick={() => perform("finalize")}
              >
                {t(
                  data.tenant_invitation && !data.already_admitted
                    ? "加入组织"
                    : "确认并继续",
                )}
              </Button>
            ) : data.existing_account ? (
              <Button
                component={RouterLink}
                to={loginHref}
                onClick={
                  data.signed_in
                    ? (event) => {
                        event.preventDefault();
                        perform("switch");
                      }
                    : undefined
                }
              >
                {t("登录已有账户")}
              </Button>
            ) : data.signed_in ? (
              <Button disabled={busy} onClick={() => perform("sign_out")}>
                {t("退出当前账户后继续注册")}
              </Button>
            ) : (
              <>
                {socialNotice}
                {registrationForm}
                {socialProviders}
                <Button component={RouterLink} to={loginHref}>
                  {t("登录已有账户")}
                </Button>
              </>
            )}
          </Stack>
        ) : data.status ? (
          <Stack spacing={3}>
            {contact && <Typography>{contact}</Typography>}
            {data.status === "pending_verification" && (
              <>
                <Alert severity="info">
                  {data.phone
                    ? t("请核对页面上显示的手机号后继续。")
                    : t("请确认页面上显示的邮箱后继续。")}
                </Alert>
                <Button
                  disabled={busy || formBusy}
                  onClick={() => perform("verify")}
                >
                  {t(data.phone ? "确认手机并继续" : "确认邮箱并继续")}
                </Button>
              </>
            )}
            {data.status === "pending_approval" && (
              <Alert severity="info">{approvalNotice}</Alert>
            )}
            {data.status === "ready" && data.signed_in && (
              <Button disabled={busy} onClick={() => perform("sign_out")}>
                {t("退出当前账户后继续注册")}
              </Button>
            )}
            {data.status === "ready" && !data.signed_in && (
              <>
                {!data.account_invitation && (
                  <>
                    <Alert severity="info">
                      {t("已有账户？请先登录，再返回此页面继续。")}
                    </Alert>
                    <Button component={RouterLink} to={loginHref}>
                      {t("登录已有账户")}
                    </Button>
                  </>
                )}
                {data.social && socialProviders}
                {socialNotice}
                {registrationForm}
              </>
            )}
          </Stack>
        ) : data.mode === "invite_only" ? (
          <Alert severity="info">
            {t("仅限邀请注册，请联系管理员获取邀请。")}
          </Alert>
        ) : methods.length === 0 ? (
          <Alert severity="warning">
            {t(
              data.social
                ? "第三方注册需要验证邮箱。邮件渠道暂不可用，请联系管理员。"
                : "当前没有可用的邮箱或短信验证渠道，暂时无法自助注册。请联系管理员。",
            )}
          </Alert>
        ) : (
          <Stack spacing={2}>
            <Stack direction="row" spacing={1}>
              {methods.includes("phone") && (
                <Button
                  variant={channel === "phone" ? "contained" : "outlined"}
                  disabled={busy || formBusy}
                  onClick={() => setChannel("phone")}
                >
                  {t("手机号注册")}
                </Button>
              )}
              {methods.includes("email") && (
                <Button
                  variant={channel === "email" ? "contained" : "outlined"}
                  disabled={busy || formBusy}
                  onClick={() => setChannel("email")}
                >
                  {t("邮箱注册")}
                </Button>
              )}
            </Stack>
            <FieldsForm
              key={channel}
              disabled={busy}
              onBusyChange={onFormBusyChange}
              fields={[
                {
                  ...(channel === "phone" ? phoneField : emailField),
                  required: true,
                },
              ]}
              submit={(v) => submit({ ...v, app: data.app })}
              label={t(channel === "phone" ? "发送验证短信" : "发送验证邮件")}
            />
            {!data.social && socialProviders}
          </Stack>
        )}
        {data.status && !completed && (
          <Stack spacing={2} sx={{ mt: 2 }}>
            {!terminal &&
              (blocked || !canAct || data.status === "pending_approval") && (
                <Button component="a" href="/sso/register">
                  {t("刷新申请进度")}
                </Button>
              )}
            {!terminal && !blocked && data.can_resend && (
              <Button
                disabled={busy || formBusy}
                onClick={() => perform("resend")}
              >
                {t("重发办理链接")}
              </Button>
            )}
            <Button
              disabled={busy || formBusy}
              onClick={() => perform("reset")}
            >
              {t("退出本次注册流程")}
            </Button>
          </Stack>
        )}
      </Panel>
      {!data.status && data.app && (
        <Button
          disabled={busy || formBusy}
          onClick={() => perform("use_account")}
        >
          {t("使用已有账号继续")}
        </Button>
      )}
      {!data.status && (
        <Button disabled={busy || formBusy} onClick={() => perform("reset")}>
          {t("退出本次注册流程")}
        </Button>
      )}
    </Container>
  );
}
export function AccountInvitationButton({
  editor,
  app,
  domains,
}: {
  editor: Actions["editor"];
  app?: string;
  domains: string[];
}) {
  return (
    <Button
      size="small"
      variant="outlined"
      color="inherit"
      onClick={() =>
        editor(
          "邀请开户",
          "/dashboard/invitations",
          invitationExceptionFields(domains, true),
          {},
          {
            app,
            delivery: "account_link",
          },
        )
      }
    >
      {t("邀请开户")}
    </Button>
  );
}

export function EnrollmentAdmin({
  data,
  mutate,
  ask,
  editor,
}: { data: ViewDataMap["EnrollmentAdminView"] } & Actions) {
  const p = data.policy;
  const inherited = (values: Values) => Boolean(values.inherit);
  const notInherited = (values: Values) => !values.inherit;
  const selfService = (values: Values) =>
    !values.inherit && values.mode === "self_service";
  return (
    <>
      <Heading
        title={t("注册策略与邀请")}
        description={
          p.app_id
            ? t("此应用可继承平台策略或独立配置。")
            : t("平台默认策略；紧急停止对所有应用生效。")
        }
      />
      <Panel title={t("注册策略")}>
        <FieldsForm
          key={`${p.app_id}-${p.version}-${data.inherited}`}
          fields={[
            ...(p.app_id
              ? [
                  {
                    name: "inherit",
                    label: t("继承平台默认策略"),
                    type: "checkbox",
                    group: "策略来源",
                    hint: t(
                      "继承后使用平台默认的注册模式、域名限制与审批要求。",
                    ),
                  },
                  {
                    name: "inherit_notice",
                    label: t(
                      "当前应用继承平台默认策略。取消勾选后可单独配置。",
                    ),
                    type: "notice",
                    group: "策略来源",
                    visibleWhen: inherited,
                  },
                ]
              : []),
            {
              name: "mode",
              label: t("注册模式"),
              group: "准入规则",
              required: true,
              visibleWhen: notInherited,
              options: [
                ["closed", t("关闭")],
                ["invite_only", t("仅邀请")],
                ["self_service", t("自助注册")],
              ],
              hint: t(
                "自助注册允许访客申请开户，已有账号可申请应用访问；仅邀请或关闭时，已有账号由管理员授予访问。",
              ),
            },
            {
              name: "domains",
              label: t("允许的邮箱域名"),
              group: "准入规则",
              visibleWhen: (values) => !values.inherit && values.mode !== "closed",
              hint: t(
                "逗号分隔，精确匹配域名。自助访问要求账号使用符合条件的已验证邮箱。签发不符合条件的邀请时须填写域名例外理由。",
              ),
            },
            {
              name: "approval_required",
              label: p.app_id ? t("自助访问需要审批") : t("自助开户需要审批"),
              group: "准入规则",
              type: "checkbox",
              visibleWhen: selfService,
              hint: p.app_id
                ? undefined
                : t("也适用于继承平台策略的应用访问申请。"),
            },
            ...(!p.app_id
              ? [
                  {
                    name: "emergency_stop",
                    label: t("紧急停止所有注册及邀请接受"),
                    type: "checkbox",
                    group: "安全开关",
                    hint: t("开启后暂停注册、接受邀请及所有应用的自助访问。"),
                  },
                ]
              : []),
          ]}
          initial={{
            ...p,
            domains: p.domains.join(","),
            inherit: data.inherited,
          }}
          submit={(v) =>
            mutate("/dashboard/registration", {
              ...v,
              app: p.app_id,
              version: p.version,
            })
          }
        />
      </Panel>
      {data.can_invite && (
        <Panel title={t("创建邀请")}>
          <FieldsForm
            fields={invitationFields(p.domains)}
            submit={(values) =>
              mutate("/dashboard/invitations", {
                ...invitationValues(values, p.domains),
                app: p.app_id,
              })
            }
            label={t("创建邀请")}
          />
        </Panel>
      )}
      <Progress data={data} admin actions={{ mutate, ask, editor }} />
    </>
  );
}
export function Admission({
  data,
  mutate,
  ask,
  editor,
}: { data: ViewDataMap["AdmissionView"] } & Actions) {
  const { error: failure, busy, run } = useAction();
  const [search, setSearch] = useState("");
  const apps = data.rows.filter(
    (r) =>
      r.status === "active" &&
      `${r.name} ${r.code} ${r.description || ""}`
        .toLocaleLowerCase()
        .includes(search.trim().toLocaleLowerCase()),
  );
  return (
    <>
      {failure && <Alert severity="error">{failure}</Alert>}
      <Heading
        title={t("应用准入与注销")}
        description={t(
          "退出应用会撤销该应用访问资格；注销账户会移除个人资料并退出所有会话。",
        )}
      />
      <Panel title={t("我的应用")}>
        <TextField
          fullWidth
          label={t("搜索应用")}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          sx={{ mb: 3 }}
        />
        {!apps.length && <Typography>{t("暂无可用应用")}</Typography>}
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: {
              xs: "1fr",
              sm: "repeat(2, 1fr)",
              lg: "repeat(3, 1fr)",
            },
            gap: 2,
          }}
        >
          {apps.map((app) => (
            <Stack
              key={app.id}
              spacing={2}
              sx={{ border: 1, borderColor: "divider", borderRadius: 2, p: 3 }}
            >
              <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
                <Avatar src={app.logo_url || undefined} variant="rounded">
                  {app.name.slice(0, 1)}
                </Avatar>
                <Typography variant="h6">{app.name}</Typography>
              </Stack>
              <Typography variant="body2" sx={{ flex: 1 }}>
                {app.description}
              </Typography>
              <Typography variant="body2">
                {app.require_mfa
                  ? t("此应用已开启 MFA")
                  : t("此应用未开启 MFA")}
              </Typography>
              {!data.mfa_enabled && !app.require_mfa ? (
                <Button component={RouterLink} to="/account/security">
                  {t("设置验证器以开启 MFA")}
                </Button>
              ) : (
                <Button
                  disabled={busy}
                  onClick={() =>
                    run(() =>
                      mutate(`/account/applications/${app.id}/mfa`, {
                        action: app.require_mfa ? "disable_mfa" : "enable_mfa",
                      }),
                    )
                  }
                >
                  {app.require_mfa
                    ? t("关闭此应用的 MFA")
                    : t("开启此应用的 MFA")}
                </Button>
              )}
              {app.homepage_url && /^https?:\/\//i.test(app.homepage_url) ? (
                <Button
                  component="a"
                  href={app.homepage_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  variant="contained"
                >
                  {t("打开应用")}
                </Button>
              ) : (
                <Typography variant="caption">
                  {t("请联系管理员配置应用主页")}
                </Typography>
              )}
            </Stack>
          ))}
        </Box>
      </Panel>
      {data.progress && (
        <Progress data={data.progress} actions={{ mutate, ask, editor }} />
      )}
      <Panel title={t("应用访问资格")}>
        <Stack spacing={2}>
          {data.rows.map((r) => {
            const explicit = r.status === "active" && !r.organization_admission;
            const pending = !explicit && r.request_status === "pending";
            const rejected =
              !explicit &&
              r.status !== "disabled" &&
              r.request_status === "rejected";
            const closed =
              !explicit &&
              r.status !== "disabled" &&
              r.request_status === "closed";
            const canApply =
              !explicit &&
              r.status !== "disabled" &&
              !r.organization_only &&
              r.self_service_open !== false;
            const endpoint = `/account/applications/${r.id}`;
            return (
              <Stack
                direction={{ xs: "column", sm: "row" }}
                spacing={2}
                sx={{
                  alignItems: { xs: "stretch", sm: "center" },
                  overflowWrap: "anywhere",
                }}
                key={r.id}
              >
                <Typography sx={{ flex: 1 }}>
                  {r.name} ·{" "}
                  {r.status ? admissionStatus(r.status) : t("尚未加入")}
                  {pending && ` · ${t("申请待审批")}`}
                  {rejected && ` · ${t("已拒绝")}`}
                  {rejected && r.request_reason && ` · ${r.request_reason}`}
                  {closed && ` · ${t("申请已关闭")}`}
                </Typography>
                {canApply && (!pending || r.opens_immediately) && (
                  <Button
                    disabled={busy}
                    onClick={() =>
                      run(() => mutate(endpoint, { action: "join" }))
                    }
                  >
                    {r.organization_admission
                      ? t("申请个人空间访问")
                      : r.opens_immediately
                        ? t("开通访问")
                        : t("申请访问")}
                  </Button>
                )}
                {pending && (
                  <Button
                    disabled={busy}
                    onClick={() =>
                      run(() => mutate(endpoint, { action: "withdraw" }))
                    }
                  >
                    {t("撤回申请")}
                  </Button>
                )}
                {!explicit &&
                  r.status !== "disabled" &&
                  r.admission_error &&
                  (!pending || r.opens_immediately) && (
                    <Stack sx={{ alignItems: "flex-start" }}>
                      <Typography>{errorText(r.admission_error)}</Typography>
                      <Button component={RouterLink} to="/account/profile">
                        {t("个人资料")}
                      </Button>
                    </Stack>
                  )}
                {r.status === "active" ? (
                  <Button
                    color="error"
                    onClick={() =>
                      ask(
                        "退出应用",
                        endpoint,
                        { action: "leave" },
                        "退出后，此应用的访问资格将被撤销。如需重新访问，请联系管理员恢复资格。",
                      )
                    }
                  >
                    {t("退出应用")}
                  </Button>
                ) : r.status === "disabled" ? (
                  <Typography>{t("请联系管理员重新授权")}</Typography>
                ) : r.organization_only ? (
                  <Typography>{t("此应用仅支持组织空间。")}</Typography>
                ) : r.self_service_open === false &&
                  !pending &&
                  !r.admission_error ? (
                  <Typography>{t("此应用暂未开放自助申请。")}</Typography>
                ) : null}
              </Stack>
            );
          })}
        </Stack>
      </Panel>
      <Panel title={t("注销账户")}>
        <Alert severity="warning" sx={{ mb: 2 }}>
          {t(
            "此操作不可恢复。所有应用资格和登录凭据将被撤销；管理员须先移除管理员身份。",
          )}
        </Alert>
        <FieldsForm
          fields={[
            {
              name: "confirmation",
              label: t("输入当前用户名确认"),
              hint: data.username,
              required: true,
            },
          ]}
          submit={(v) => {
            ask(
              "永久注销账户",
              "/account/close",
              v,
              "确认删除个人资料并撤销全部访问资格？",
            );
            return Promise.resolve();
          }}
          label={t("注销账户")}
          submitColor="error"
        />
      </Panel>
    </>
  );
}

function Progress({
  data,
  admin = false,
  actions,
}: {
  data: ProgressList;
  admin?: boolean;
  actions: Actions;
}) {
  const [params, setParams] = useSearchParams();
  const { error: failure, busy, run } = useAction();
  const update = (values: Record<string, unknown>) => {
    const next = new URLSearchParams(params);
    next.delete("page");
    Object.entries(values).forEach(([k, v]) =>
      typeof v === "boolean" || v ? next.set(k, String(v)) : next.delete(k),
    );
    setParams(next, { flushSync: true });
    return Promise.resolve();
  };
  return (
    <Panel title={admin ? t("最近申请与邀请") : t("我的申请与邀请")}>
      {failure && <Alert severity="error">{failure}</Alert>}
      {admin && (
        <Typography sx={{ mb: 2 }}>
          {t("待审批 {{0}} 项", { "0": data.pending_count || 0 })}
        </Typography>
      )}
      <FieldsForm
        compact
        submitSize="small"
        key={params.toString()}
        fields={[
          { name: "q", label: t("搜索邮箱或应用") },
          {
            name: "status",
            label: t("状态"),
            options: [
              ["", t("全部")],
              ...[
                "pending_verification",
                "pending_approval",
                "ready",
                "completed",
                "rejected",
                "revoked",
                "expired",
              ].map((s) => [s, admissionStatus(s)] as [string, string]),
            ],
          },
          ...(admin
            ? [{ name: "all_apps", label: t("跨应用查询"), type: "checkbox" }]
            : []),
        ]}
        initial={{
          q: params.get("q") || "",
          status: params.get("status") || "",
          all_apps: params.has("all_apps")
            ? params.get("all_apps") === "true"
            : !params.has("app"),
        }}
        submit={update}
        label={t("查询")}
      />
      <Stack spacing={2} sx={{ mt: 3 }}>
        {data.rows.length === 0 && <Typography>{t("暂无记录")}</Typography>}
        {data.rows.map((r) => (
          <Stack
            key={r.id}
            spacing={1}
            sx={{
              borderBottom: 1,
              borderColor: "divider",
              pb: 2,
              overflowWrap: "anywhere",
            }}
          >
            <Typography>
              {r.email || t("无联系方式")} · {r.app_name || t("平台账户")} ·{" "}
              {r.invitation ? t("邀请") : t("申请")} ·{" "}
              {admissionStatus(r.status)}
            </Typography>
            <Typography variant="caption">
              {date(r.created_at)} ·{" "}
              {labelValue("到期时间", date(r.expires_at))}
            </Typography>
            {r.reason && <Typography variant="body2">{r.reason}</Typography>}
            <Stack
              direction="row"
              sx={{ flexWrap: "wrap", alignItems: "center", gap: 1 }}
            >
              {admin && r.status === "pending_approval" && (
                <>
                  <Button
                    onClick={() =>
                      actions.ask(
                        "批准申请",
                        `/dashboard/enrollments/${r.id}`,
                        { action: "approve" },
                      )
                    }
                  >
                    {t("批准")}
                  </Button>
                  <Button
                    color="warning"
                    onClick={() =>
                      actions.editor(
                        "拒绝原因",
                        `/dashboard/enrollments/${r.id}`,
                        [
                          {
                            name: "reason",
                            label: "拒绝原因",
                            multiline: true,
                          },
                        ],
                        {},
                        { action: "reject" },
                      )
                    }
                  >
                    {t("拒绝")}
                  </Button>
                </>
              )}
              {["pending_verification", "pending_approval", "ready"].includes(
                r.status,
              ) && (
                <>
                  {!admin && (
                    <Button
                      disabled={busy}
                      onClick={() =>
                        run(() =>
                          actions.mutate(`/account/enrollments/${r.id}`, {
                            action: "continue",
                          }),
                        )
                      }
                    >
                      {t("继续办理")}
                    </Button>
                  )}
                  {admin && r.invitation && (
                    <Button
                      onClick={() =>
                        actions.ask(
                          "获取激活链接",
                          `/dashboard/enrollments/${r.id}`,
                          { action: "issue_link" },
                          "将签发新链接，旧链接会立即失效。",
                        )
                      }
                    >
                      {t("获取激活链接")}
                    </Button>
                  )}
                  {r.email && (
                    <Button
                      onClick={() =>
                        actions.ask(
                          "重发邮件",
                          `${admin ? "/dashboard" : "/account"}/enrollments/${r.id}`,
                          { action: "resend" },
                        )
                      }
                    >
                      {t("重发")}
                    </Button>
                  )}
                  <Button
                    color="warning"
                    onClick={() =>
                      actions.ask(
                        admin ? "撤销流程" : "撤回申请",
                        `${admin ? "/dashboard" : "/account"}/enrollments/${r.id}`,
                        { action: admin ? "revoke" : "withdraw" },
                      )
                    }
                  >
                    {admin ? t("撤销") : t("撤回")}
                  </Button>
                </>
              )}
            </Stack>
          </Stack>
        ))}
        <Pagination
          page={data.page || 1}
          count={Math.max(1, data.total_pages || 1)}
          onChange={(_, page) => {
            const next = new URLSearchParams(params);
            next.set("page", String(page));
            setParams(next, { flushSync: true });
          }}
        />
      </Stack>
    </Panel>
  );
}
export function AppMembers({
  data,
  mutate,
  ask,
  editor,
}: { data: ViewDataMap["AppMembersView"] } & Actions) {
  const [params, setParams] = useSearchParams();
  const endpoint = `/dashboard/apps/${data.app_id}/members`;
  const canManage =
    !data.system && can(data.layout, "apps.members.manage", data.app_id);
  const requestsPage = data.requests_page || 1;
  function showRequestsPage(page: number) {
    const next = new URLSearchParams(params);
    next.set("requests_page", String(page));
    setParams(next);
  }
  return (
    <>
      <Heading
        title={t("应用成员")}
        description={data.app_name}
        back={`/dashboard/apps/${data.app_id}`}
      />
      <Panel title={t("查询成员")}>
        <FieldsForm
          fields={[
            { name: "q", label: t("用户名或昵称") },
            {
              name: "status",
              label: t("状态"),
              options: [
                ["", t("全部")],
                ["active", t("已启用")],
                ["disabled", t("已停用")],
              ],
            },
          ]}
          initial={{
            q: params.get("q") || "",
            status: params.get("status") || "",
          }}
          submit={(v) => {
            const next = new URLSearchParams();
            Object.entries(v).forEach(([k, v]) => v && next.set(k, String(v)));
            setParams(next, { flushSync: true });
            return Promise.resolve();
          }}
          label={t("查询")}
        />
      </Panel>
      {canManage && (
        <Panel title={t("待审访问申请")}>
          <Stack spacing={2}>
            {!data.requests?.length && <Typography>{t("暂无记录")}</Typography>}
            {data.requests?.map((request) => (
              <Stack
                key={request.id}
                direction="row"
                spacing={1}
                sx={{ alignItems: "center" }}
              >
                <Typography sx={{ flex: 1 }}>{request.username}</Typography>
                <Button
                  onClick={() =>
                    ask("批准", endpoint, {
                      action: "approve",
                      request_id: request.id,
                    })
                  }
                >
                  {t("批准")}
                </Button>
                <Button
                  onClick={() =>
                    editor(
                      "拒绝",
                      endpoint,
                      [{ name: "reason", label: t("拒绝原因") }],
                      {},
                      { action: "reject", request_id: request.id },
                    )
                  }
                >
                  {t("拒绝")}
                </Button>
              </Stack>
            ))}
            {(requestsPage > 1 || data.more_requests) && (
              <Stack direction="row" spacing={1}>
                <Button
                  disabled={requestsPage === 1}
                  onClick={() => showRequestsPage(requestsPage - 1)}
                >
                  {t("上一页")}
                </Button>
                <Button
                  disabled={!data.more_requests}
                  onClick={() => showRequestsPage(requestsPage + 1)}
                >
                  {t("下一页")}
                </Button>
              </Stack>
            )}
          </Stack>
        </Panel>
      )}
      {canManage && (
        <Panel title={t("添加成员")}>
          <FieldsForm
            fields={[
              { name: "username", label: t("完整用户名"), required: true },
            ]}
            submit={(v) => mutate(endpoint, { ...v, action: "grant" })}
            label={t("授予访问资格")}
          />
        </Panel>
      )}
      <Panel title={t("应用成员")}>
        <Stack spacing={2}>
          {!data.rows.length && <Typography>{t("暂无记录")}</Typography>}
          {data.rows.map((r) => (
            <Stack
              key={r.user_id}
              direction={{ xs: "column", sm: "row" }}
              spacing={2}
              sx={{
                alignItems: { xs: "stretch", sm: "center" },
                overflowWrap: "anywhere",
              }}
            >
              <Typography sx={{ flex: 1 }}>
                {r.nickname || r.username} · {r.username} ·{" "}
                {admissionStatus(r.status)}
              </Typography>
              {canManage && (
                <Button
                  onClick={() =>
                    ask(
                      r.status === "active"
                        ? t("撤销应用访问")
                        : t("授予访问资格"),
                      endpoint,
                      {
                        action: r.status === "active" ? "revoke" : "restore",
                        user_id: r.user_id,
                        username: r.username,
                      },
                    )
                  }
                >
                  {r.status === "active" ? t("撤销") : t("恢复访问")}
                </Button>
              )}
            </Stack>
          ))}
          <Pagination
            page={data.page}
            count={Math.max(1, data.total_pages)}
            onChange={(_, page) => {
              const next = new URLSearchParams(params);
              next.set("page", String(page));
              setParams(next, { flushSync: true });
            }}
          />
        </Stack>
      </Panel>
    </>
  );
}
