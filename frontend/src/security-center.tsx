import { Alert, Box, Button, Stack, Typography } from "@mui/material";
import { useLocation, Link as RouterLink } from "react-router-dom";
import { FieldsForm } from "./forms";
import { Heading, Panel, type Actions } from "./shared";
import type { ViewDataMap } from "./contracts";
import { t, useLocale } from "./i18n";
import { errorText } from "./api";
export function SecurityCenter({
  data: d,
  mutate,
}: { data: ViewDataMap["SecurityView"] } & Pick<Actions, "mutate">) {
  useLocale();
  const { pathname } = useLocation();
  const reauth = pathname === "/account/reauth";
  const authenticationPending = d.pending || d.recovery;
  const submit = (
    action: string,
    values: Record<string, string | boolean | number | null | undefined> = {},
  ) => mutate(pathname, { ...values, action, redirect: d.redirect });
  return (
    <Box sx={{ maxWidth: 720, mx: "auto" }}>
      <Heading
        title={t(reauth ? "重新验证身份" : "账户安全")}
        description={t("管理验证器和账户恢复方式。")}
      />
      {d.error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {errorText(d.error)}
        </Alert>
      )}
      {d.required && !d.enabled && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          {t("管理员必须启用双重验证后才能继续。")}
        </Alert>
      )}
      {d.recovery && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          {t("恢复码已使用，请重新绑定验证器以恢复账户访问。")}
        </Alert>
      )}
      {!!d.codes.length ? (
        <Panel title={t("保存恢复码")}>
          <Alert severity="warning">
            {t("恢复码仅显示一次，请离线保存。每个恢复码只能使用一次。")}
          </Alert>
          <Box
            component="pre"
            sx={{ whiteSpace: "pre-wrap", userSelect: "all" }}
          >
            {d.codes.join("\n")}
          </Box>
          <Button component={RouterLink} to={d.redirect}>
            {t("已保存，继续")}
          </Button>
        </Panel>
      ) : reauth ? (
        <Panel title={t("重新验证身份")}>
          {d.has_password ? (
            <FieldsForm
              fields={[
                {
                  name: "password",
                  label: t("当前密码"),
                  type: "password",
                  required: true,
                },
                ...(d.enabled
                  ? [{ name: "code", label: t("验证器验证码"), required: true }]
                  : []),
              ]}
              submit={(v) => submit("reauth", v)}
            />
          ) : !d.providers?.length ? (
            <Alert severity="warning">
              {t("当前账号没有本地密码或可用的 OIDC 身份，暂不支持重新验证。")}
            </Alert>
          ) : (
            <Stack spacing={2.5}>
              <Typography>
                {t("使用已绑定的 OIDC 账号重新验证，然后输入验证器验证码。")}
              </Typography>
              <Stack spacing={1.5}>
                {d.providers?.map((p) => (
                  <FieldsForm
                    key={p.key}
                    fields={[]}
                    label={p.name}
                    submit={() =>
                      mutate(`/account/reauth/${encodeURIComponent(p.key)}`, {
                        redirect: d.redirect,
                      })
                    }
                  />
                ))}
              </Stack>
              <FieldsForm
                fields={
                  d.enabled
                    ? [
                        {
                          name: "code",
                          label: t("验证器验证码"),
                          required: true,
                        },
                      ]
                    : []
                }
                submit={(v) => submit("reauth", v)}
              />
            </Stack>
          )}
        </Panel>
      ) : d.pending && d.enabled && !d.recovery ? (
        <>
          <Panel title={t("双重验证")}>
            <FieldsForm
              fields={[
                { name: "code", label: t("验证器验证码"), required: true },
              ]}
              label={t("验证并继续")}
              submit={(v) => submit("verify", v)}
            />
          </Panel>
          <Panel title={t("无法使用验证器？")}>
            <FieldsForm
              fields={[{ name: "code", label: t("恢复码"), required: true }]}
              submit={(v) => submit("recover", v)}
              label={t("使用恢复码")}
            />
          </Panel>
        </>
      ) : !d.enabled || d.recovery ? (
        <Panel title={t("设置验证器")}>
          {d.secret ? (
            <Stack spacing={2.5}>
              <Typography>
                {t("扫描二维码或在验证器中手动输入密钥，再输入验证码确认。")}
              </Typography>
              <Box
                component="img"
                src={`data:image/png;base64,${d.qr}`}
                alt={t("验证器二维码")}
                sx={{ width: 220, maxWidth: "100%", alignSelf: "center" }}
              />
              <Box
                component="pre"
                sx={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}
              >
                {d.secret}
              </Box>
              <FieldsForm
                fields={[
                  { name: "code", label: t("验证器验证码"), required: true },
                ]}
                submit={(v) => submit("enable", v)}
                label={t("启用双重验证")}
              />
            </Stack>
          ) : (
            <FieldsForm
              fields={[]}
              submit={() => submit("setup")}
              label={t("开始设置")}
            />
          )}
        </Panel>
      ) : (
        <>
          <Panel title={t("双重验证已启用")}>
            <Stack spacing={3}>
              <Typography>{t("每次新登录都需要验证器验证码。")}</Typography>
              <FieldsForm
                fields={[
                  { name: "code", label: t("验证器验证码"), required: true },
                ]}
                submit={(v) => submit("codes", v)}
                label={t("重新生成恢复码")}
              />
              {!d.required && (
                <FieldsForm
                  fields={[
                    { name: "code", label: t("验证器验证码"), required: true },
                  ]}
                  submit={(v) => submit("disable", v)}
                  label={t("关闭双重验证")}
                />
              )}
            </Stack>
          </Panel>
        </>
      )}
      <Stack
        direction="row"
        sx={{ flexWrap: "wrap", alignItems: "center", gap: 1 }}
      >
        {(d.pending || d.recovery) && (
          <FieldsForm
            fields={[]}
            submitSize="medium"
            label={t("退出登录")}
            submit={() => mutate("/account/logout")}
          />
        )}
        <Button component={RouterLink} to="/account/login">
          {t("重新登录")}
        </Button>
        <Button
          component={RouterLink}
          to="/account/change-password"
          disabled={authenticationPending}
        >
          {t("管理密码")}
        </Button>
        <Button
          component={RouterLink}
          to="/account/reauth?redirect=%2Faccount%2Fsecurity"
        >
          {t("重新验证身份")}
        </Button>
        <Button
          component={RouterLink}
          to="/account/profile"
          disabled={authenticationPending}
        >
          {t("返回个人中心")}
        </Button>
      </Stack>
    </Box>
  );
}
export function AdminRoles({
  data,
  mutate,
}: { data: ViewDataMap["AdminRolesView"] } & Pick<Actions, "mutate">) {
  useLocale();
  return (
    <>
      <Heading
        title={t("管理员")}
        description={t("超级管理员拥有所有权限；普通管理员暂未分配管理权限。")}
      />
      <Panel title={t("管理员列表")}>
        {data.rows.map((r) => (
          <Typography key={r.user_id}>
            {r.username} ·{" "}
            {t(r.role === "super_admin" ? "超级管理员" : "普通管理员")}
          </Typography>
        ))}
      </Panel>
      <Panel title={t("设置管理员角色")}>
        <FieldsForm
          fields={[
            { name: "username", label: t("用户名"), required: true },
            {
              name: "role",
              label: t("角色"),
              required: true,
              options: [
                ["super_admin", t("超级管理员")],
                ["admin", t("普通管理员")],
                ["remove", t("移除管理员")],
              ],
            },
          ]}
          submit={(v) => mutate("/dashboard/admins", v)}
        />
      </Panel>
    </>
  );
}
