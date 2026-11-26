import { IdentityGraphic } from "./components/identity-graphic";
import { FilingLink } from "./components/filing-link";
import { CheckCircleRounded } from "@mui/icons-material";
import {
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  Stack,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from "@mui/material";
import { useState } from "react";
import { useAction } from "./use-action";
import { Link as RouterLink, useLocation } from "react-router-dom";
import { errorText } from "./api";
import type { ViewEnvelope, AuthView } from "./contracts";
import { FieldsForm, type Field } from "./forms";
import { t, useLocale } from "./i18n";
import { LanguageSwitcher } from "./language-switcher";
import { Brand } from "./layout";

import { type Actions } from "./shared";
export function Auth({
  page,
  mutate,
}: {
  page: ViewEnvelope<AuthView>;
  mutate: Actions["mutate"];
}) {
  useLocale();
  const { view, data } = page;
  const location = useLocation();
  const [identifierType, setIdentifierType] = useState("username");
  const {
    busy: actionBusy,
    error: actionFailure,
    run,
    clearError,
  } = useAction();
  const [formBusy, setFormBusy] = useState(false);
  const runAction = (
    values: Parameters<typeof mutate>[1],
    endpoint = location.pathname,
  ) => run(() => mutate(endpoint, values));
  const login = view === "LoginView" || view === "AccountLoginView",
    forgot = view === "ForgotPasswordView",
    reset = view === "ResetPasswordView";
  const resetUnavailable =
    reset &&
    ["missing_token", "invalid_token", "token_already_used"].includes(
      data.error,
    );
  const done = view === "EndSessionView",
    error = ["ErrorView", "ForbiddenView"].includes(view);
  let title =
    view === "AppAccessDeniedView"
      ? t(data.expired ? "授权请求已失效" : "暂无应用访问权限")
      : view === "SelectAccountView"
        ? t("选择账号")
        : login
          ? t("欢迎回来")
          : forgot
            ? t("找回密码")
            : reset
              ? t("设置新密码")
              : view === "ConsentView"
                ? t("授权应用访问")
                : view === "SocialLinkView"
                  ? t("关联已有账户")
                  : view === "ConfirmLogoutView"
                    ? t("确认退出登录")
                    : done
                      ? t("你已安全退出")
                      : t("暂时无法访问");
  let content: React.ReactNode;
  if (view === "AppAccessDeniedView") {
    const recover = (action: string) =>
      runAction({ action, token: data.token }, "/oauth2/authorize/access");
    content = (
      <Stack spacing={2}>
        <Alert severity="warning">
          {data.expired
            ? t(
                "本次授权已过期、已结束或登录账号已变化。请返回原应用重新发起登录。",
              )
            : t("账号 {{0}} 尚无 {{1}} 的访问资格。", {
                "0": data.username,
                "1": data.app_name,
              })}
        </Alert>
        {!data.expired && (
          <>
            <Typography color="text.secondary">
              {data.system
                ? t("请联系管理员开通此应用权限，完成后回到本页重试。")
                : t(
                    "请在新窗口申请或查看应用访问资格；审批通过后，回到本页重试。若资格已被停用，请联系管理员。",
                  )}
            </Typography>
            {!data.system && (
              <Button
                component="a"
                href="/account/applications"
                target="_blank"
                rel="noopener noreferrer"
                variant="outlined"
              >
                {t("申请或查看访问资格")}
              </Button>
            )}
            <Button
              variant="contained"
              disabled={actionBusy}
              onClick={() => recover("retry")}
            >
              {t("已获得权限，重新尝试")}
            </Button>
            <Button
              variant="outlined"
              disabled={actionBusy}
              onClick={() => recover("other")}
            >
              {t("登录其他账号")}
            </Button>
            <Button
              color="inherit"
              disabled={actionBusy}
              onClick={() => recover("cancel")}
            >
              {t("取消并返回个人中心")}
            </Button>
          </>
        )}
        {data.expired && (
          <Button
            component={RouterLink}
            to="/account/profile"
            variant="contained"
          >
            {t("返回个人中心")}
          </Button>
        )}
      </Stack>
    );
  } else if (view === "SelectAccountView") {
    content = (
      <Stack spacing={2}>
        <Typography>{t("请选择继续使用当前账号，或登录其他账号。")}</Typography>
        {data.username && (
          <Button
            variant="contained"
            disabled={actionBusy || formBusy}
            onClick={() =>
              runAction({
                action: "current",
                token: data.token,
                redirect: data.redirect,
              })
            }
          >
            {t("继续使用 {{0}}", { "0": data.username })}
          </Button>
        )}
        <Button
          variant="outlined"
          disabled={actionBusy || formBusy}
          onClick={() =>
            runAction({
              action: "other",
              token: data.token,
              redirect: data.redirect,
            })
          }
        >
          {t("登录其他账号")}
        </Button>
      </Stack>
    );
  } else if (login || forgot || reset) {
    let fields: Field[] = login
      ? [
          {
            name: "identifier",
            label:
              identifierType === "username"
                ? t("用户名")
                : identifierType === "email"
                  ? t("邮箱")
                  : t("手机号"),
            required: true,
          },
          {
            name: "password",
            label: t("密码"),
            type: "password",
            required: true,
            autoComplete: "current-password",
          },
        ]
      : forgot
        ? [
            {
              name: "identifier",
              label: t("邮箱或完整手机号"),
              required: true,
            },
          ]
        : [
            {
              name: "new_password",
              label: t("新密码"),
              type: "password",
              required: true,
            },
            {
              name: "confirm_password",
              label: t("确认新密码"),
              type: "password",
              required: true,
              validate: (value, values) =>
                value && value !== values.new_password
                  ? t("两次输入的密码不一致")
                  : undefined,
            },
          ];
    content = (
      <>
        {forgot && (
          <Alert severity="info" sx={{ mb: 3 }}>
            {t(
              "已验证邮箱或手机号可用于设置或重置本地密码，此操作不会关闭双重验证。",
            )}
          </Alert>
        )}
        {"success" in data && data.success && (
          <Alert severity="success" sx={{ mb: 3 }}>
            {forgot
              ? t("如果账户可恢复，你将收到重置密码的通知。")
              : t("密码已更新，请返回登录。")}
          </Alert>
        )}
        {login && (
          <ToggleButtonGroup
            exclusive
            fullWidth
            size="small"
            value={identifierType}
            disabled={actionBusy || formBusy}
            onChange={(_, value) => value && setIdentifierType(value)}
            aria-label={t("登录方式")}
            sx={{
              mb: 3,
              "& .MuiToggleButton-root": {
                py: 0.75,
                fontWeight: 600,
                fontSize: 13,
                textTransform: "none",
                borderColor: "divider",
              },
            }}
          >
            {[
              ["username", t("用户名")],
              ["email", t("邮箱")],
              ["phone", t("手机号")],
            ].map(([value, label]) => (
              <ToggleButton key={value} value={value}>
                {label}
              </ToggleButton>
            ))}
          </ToggleButtonGroup>
        )}
        {resetUnavailable && (
          <Stack spacing={2}>
            <Alert severity="error">{errorText(data.error)}</Alert>
            <Button
              component={RouterLink}
              to="/sso/forgot-password"
              variant="contained"
              color="inherit"
            >
              {t("重新申请重置链接")}
            </Button>
          </Stack>
        )}
        {!resetUnavailable && !(reset && "success" in data && data.success) && (
          <FieldsForm
            fullWidthSubmit
            key={view}
            serverError={data.error ? errorText(data.error) : ""}
            onBusyChange={(busy) => {
              setFormBusy(busy);
              if (busy) clearError();
            }}
            fields={fields}
            submit={async (values) => {
              await mutate(location.pathname + location.search, {
                ...values,
                identifier_type: identifierType,
                redirect: "redirect" in data ? data.redirect : "",
              });
            }}
            label={
              login ? t("登录") : forgot ? t("发送恢复通知") : t("保存新密码")
            }
          />
        )}
        <Stack direction="row" sx={{ justifyContent: "space-between", mt: 3 }}>
          <Button
            component={RouterLink}
            to={login ? "/sso/register" : "/sso/login"}
            size="small"
          >
            {login ? t("创建账户") : t("返回登录")}
          </Button>
          {login && (
            <Button
              component={RouterLink}
              to="/sso/forgot-password"
              size="small"
              color="inherit"
            >
              {t("忘记密码？")}
            </Button>
          )}
        </Stack>
        {login && !!data.providers?.length && (
          <>
            <Divider sx={{ my: 3 }}>{t("其他登录方式")}</Divider>
            <Stack
              direction="row"

              sx={{ justifyContent: "center", flexWrap: "wrap", gap: 1 }}
            >
              {data.providers.map((p) => (
                <Button
                  key={p.key}
                  component="a"
                  disabled={formBusy}
                  href={`/sso/social/${encodeURIComponent(p.key || "")}/login${"redirect" in data && data.redirect ? `?redirect=${encodeURIComponent(data.redirect)}` : ""}`}
                  variant="outlined"
                >
                  {p.name}
                </Button>
              ))}
            </Stack>
          </>
        )}
      </>
    );
  } else if (view === "ConsentView")
    content = (
      <>
        {data.session_takeover && (
          <Typography color="warning.main" sx={{ mb: 2 }}>
            {t("需要确认应用登录。继续后可能退出此应用的其他设备，不影响其他应用。")}
          </Typography>
        )}
        <Typography color="text.secondary" sx={{ mb: 3 }}>
          <strong>{data.client_name}</strong>{" "}
          {t("希望访问以下账户信息。你当前以")} {data.user_name} {t("登录。")}
        </Typography>
        <Stack spacing={1} sx={{ mb: 3 }}>
          {data.scopes?.map((scope) => (
            <Stack direction="row" spacing={1} key={scope}>
              <CheckCircleRounded color="primary" fontSize="small" />
              <Typography>
                {(
                  {
                    openid: t("确认你的身份"),
                    profile: t("读取基本资料"),
                    email: t("读取邮箱信息"),
                    phone: t("读取手机号"),
                  } as Record<string, string>
                )[scope] || scope}
              </Typography>
            </Stack>
          ))}
        </Stack>
        <FieldsForm
          fullWidthSubmit
          fields={[]}
          label={data.session_takeover ? t("确认并继续登录") : t("允许访问")}
          disabled={actionBusy}
          onBusyChange={(busy) => {
            setFormBusy(busy);
            if (busy) clearError();
          }}
          submit={() =>
            mutate("/sso/consent", {
              action: data.session_takeover ? "allow_takeover" : "allow",
              request_token: data.request_token,
            })
          }
          footer={
            <Button
              color="inherit"
              disabled={actionBusy || formBusy}
              onClick={() =>
                runAction(
                  {
                    action: "deny",
                    request_token: data.request_token,
                  },
                  "/sso/consent",
                )
              }
            >
              {t("拒绝授权")}
            </Button>
          }
        />
      </>
    );
  else if (view === "SocialLinkView")
    content = (
      <>
        <Alert severity="info" sx={{ mb: 3 }}>
          {data.provider_name} {t("登录信息与已有账户")}
          {data.account_email} {t("一致。")}
          {data.has_password && t("输入该账户密码以关联。")}
        </Alert>
        {data.has_password ? (
          <FieldsForm
            fullWidthSubmit
            serverError={data.error ? errorText(data.error) : ""}
            fields={[
              {
                name: "password",
                label: t("已有账户密码"),
                autoComplete: "current-password",
                type: "password",
                required: true,
              },
            ]}
            label={t("确认关联")}
            submit={(values) =>
              mutate("/sso/social/link", { ...values, nonce: data.nonce })
            }
          />
        ) : (
          <>
            <Alert severity="info" sx={{ mb: 3 }}>
              {t(
                "此账户尚未设置密码。请使用原登录方式进入账户，设置本地密码后，重新发起本次第三方登录以完成关联。",
              )}
            </Alert>
            <Button
              component={RouterLink}
              to="/account/login?redirect=%2Faccount%2Fchange-password"
              fullWidth
              variant="contained"
              color="inherit"
            >
              {t("登录原账户并设置密码")}
            </Button>
          </>
        )}
      </>
    );
  else if (view === "ConfirmLogoutView")
    content = (
      <>
        <Typography color="text.secondary" sx={{ mb: 3 }}>
          {t("确认退出当前账户？退出后，你需要重新登录才能继续访问。")}
        </Typography>
        <FieldsForm
          fullWidthSubmit
          fields={[]}
          label={t("确认退出")}
          submit={() =>
            mutate("/oauth2/session/end", {
              confirm: "yes",
              session_id: data.session_id,
              id_token_hint: data.id_token_hint,
              post_logout_redirect_uri: data.post_logout_redirect_uri,
              state: data.state,
            })
          }
        />
        <Button
          component={RouterLink}
          to="/account/profile"
          fullWidth
          sx={{ mt: 2 }}
        >
          {t("取消并返回个人中心")}
        </Button>
      </>
    );
  else
    content = (
      <>
        <Alert severity={done ? "success" : "warning"} sx={{ mb: 3 }}>
          {done
            ? t("当前登录会话已退出。")
            : view === "ForbiddenView"
              ? t("你的账户没有此工作空间的管理权限。")
              : t("请求无法完成（{{0}}）", {
                  "0": data && "code" in data ? data.code : "404",
                })}
        </Alert>
        <Button
          component={RouterLink}
          to="/"
          fullWidth
          variant="contained"
          color="inherit"
        >
          {t("返回首页")}
        </Button>
      </>
    );
  return (
    <Box
      sx={{
        minHeight: "100dvh",
        display: "grid",
        gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" },
        bgcolor: "background.default",
      }}
    >
      <Stack
        sx={{
          display: { xs: "none", md: "flex" },
          position: "relative",
          overflow: "hidden",
          p: 6,
          background:
            "linear-gradient(155deg,#f2f7ff 0%,#eef3ff 48%,#f8f5ff 100%)",
          borderRight: 1,
          borderColor: "divider",
        }}
      >
        <Box
          aria-hidden
          sx={{
            position: "absolute",
            width: 520,
            height: 520,
            borderRadius: "50%",
            border: "1px solid rgba(24,119,242,.10)",
            top: -160,
            right: -180,
          }}
        />
        <Box
          aria-hidden
          sx={{
            position: "absolute",
            width: 320,
            height: 320,
            borderRadius: "50%",
            border: "1px solid rgba(99,102,241,.12)",
            bottom: -120,
            left: -100,
          }}
        />
        <Box sx={{ position: "relative" }}>
          <Brand />
        </Box>
        <Stack
          sx={{
            position: "relative",
            flex: 1,
            maxWidth: 460,
            mx: "auto",
            justifyContent: "center",
            width: "100%",
          }}
          spacing={2.5}
        >
          <Chip
            label="PERO IDENTITY"
            sx={{
              alignSelf: "flex-start",
              bgcolor: "rgba(255,255,255,.72)",
              border: 1,
              borderColor: "divider",
            }}
          />
          <Typography variant="h2" sx={{ fontSize: { md: 40, lg: 44 } }}>
            {t("一个账户，")}
            <br />
            {t("连接你的世界。")}
          </Typography>
          <Typography color="text.secondary" sx={{ maxWidth: 380 }}>
            {t("从身份验证到日常管理，让每一次访问都简单、安全。")}
          </Typography>
          <Box sx={{ py: 2, display: "flex", justifyContent: "center" }}>
            <IdentityGraphic variant="auth" />
          </Box>
        </Stack>
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ position: "relative" }}
        >
          OAuth 2.0 · OpenID Connect · Single Sign-On
        </Typography>
      </Stack>
      <Box
        sx={{
          position: "relative",
          display: "flex",
          flexDirection: "column",
          minWidth: 0,
        }}
      >
        <Stack
          direction="row"
          sx={{
            alignItems: "center",
            justifyContent: "space-between",
            gap: 2,
            px: { xs: 2.5, sm: 3, md: 4 },
            py: { xs: 2, md: 2.5 },
            minHeight: 64,
          }}
        >
          <Box sx={{ display: { md: "none" }, minWidth: 0 }}>
            <Brand />
          </Box>
          <Box sx={{ ml: "auto", flexShrink: 0 }}>
            <LanguageSwitcher />
          </Box>
        </Stack>
        <Box
          sx={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            px: { xs: 2.5, sm: 3 },
            pb: { xs: 5, md: 8 },
          }}
        >
          <Box sx={{ width: "100%", maxWidth: 440, minWidth: 0 }}>
            <Typography variant="h3" sx={{ mb: 1, fontSize: { xs: 26, md: 30 } }}>
              {t(title)}
            </Typography>
            <Typography color="text.secondary" sx={{ mb: 4 }}>
              {error
                ? t("检查访问地址或联系管理员。")
                : done
                  ? t("感谢使用 Pero。")
                  : t("你的数字身份，从这里开始。")}
            </Typography>
            {actionFailure && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {t(actionFailure)}
              </Alert>
            )}
            {content}
            {!done && !error && view !== "AppAccessDeniedView" && (
              <Button
                component={RouterLink}
                to="/"
                size="small"
                color="inherit"
                sx={{ display: "flex", mx: "auto", mt: 4 }}
              >
                {t("返回首页")}
              </Button>
            )}
            <Box component="footer" sx={{ mt: 4, textAlign: "center" }}>
              <FilingLink />
            </Box>
          </Box>
        </Box>
      </Box>
    </Box>
  );
}
