import { can, isSuper } from "./permissions";
import { AddRounded, EditRounded } from "@mui/icons-material";
import { Alert, Box, Button, Card, Stack, Typography } from "@mui/material";
import { Link as RouterLink } from "react-router-dom";
import { date, lower, errorText } from "./api";
import type { ViewEnvelope, DetailView } from "./contracts";
import { clientFields, keyFields } from "./forms";
import { t, useLocale } from "./i18n";
import { Empty, Heading, Panel, Status, names, type Actions } from "./shared";

export function ManagementDetail({
  page,
  ask,
  editor,
}: { page: ViewEnvelope<DetailView> } & Actions) {
  const { view, data } = page;
  const allowed = (p: string) =>
    can(
      data.layout,
      p,
      page.view === "AppDetailView" ? page.data.app.id : undefined,
    );
  const superAdmin = isSuper(data.layout);
  useLocale();
  const isApp = view === "AppDetailView",
    isUser = view === "UserDetailView",
    kind = isApp ? "apps" : isUser ? "users" : "providers";
  const row = isApp ? data.app : isUser ? data.user : data.provider;
  const name = isApp
    ? data.app.name
    : isUser
      ? data.user.nickname || data.user.username
      : data.provider.name;
  const status = isApp
    ? data.app.status
    : isUser
      ? data.user.status
      : data.provider.enabled;
  const base = `/dashboard/${kind}/${row.id}`;
  const system = isApp
    ? data.app.system
    : !isUser && lower(data.provider.kind) === "local";
  const props: [string, string | null][] = isUser
    ? [
        [t("用户名"), data.user.username],
        [t("邮箱"), data.user.email],
        [t("手机"), data.user.phone],
        [t("注册时间"), date(data.user.created_at)],
      ]
    : isApp
      ? [
          [t("应用标识"), data.app.code],
          [t("类型"), lower(data.app.type)],
          [t("主页"), data.app.homepage_url],
          [t("说明"), data.app.description],
        ]
      : [
          [t("标识"), data.provider.code],
          [t("协议"), lower(data.provider.kind)],
          ["Issuer", data.provider.issuer],
          ["Client ID", data.provider.client_id],
        ];
  return (
    <>
      <Heading
        title={name}
        description={t("{{0}}详情 · {{1}}", {
          "0": t(names[kind]),
          "1": row.id,
        })}
        back={`/dashboard/${kind}`}
        action={
          (isApp
            ? allowed("apps.manage")
            : isUser
              ? allowed("users.update") || allowed("users.contact.update")
              : superAdmin && !system) && (
            <Button
              component={RouterLink}
              to={`${base}/edit`}
              variant="contained"
              color="inherit"
              startIcon={<EditRounded />}
            >
              {t("编辑")}
            </Button>
          )
        }
      />
      {data.error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {errorText(data.error)}
        </Alert>
      )}
      {isUser && superAdmin && (
        <Button component={RouterLink} to={`${base}/security`} sx={{ mb: 2 }}>
          {t("会话与登录锁定")}
        </Button>
      )}
      {isApp && superAdmin && (
        <Button
          component={RouterLink}
          to={`${base}/integration`}
          sx={{ mb: 2 }}
        >
          {t("接入向导与诊断")}
        </Button>
      )}
      {isApp && !system && (
        <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
          <Button
            sx={{ display: superAdmin ? undefined : "none" }}
            component={RouterLink}
            to={`/dashboard/registration?app=${row.id}`}
          >
            {t("注册策略与邀请")}
          </Button>
          <Button
            component={RouterLink}
            sx={{ display: allowed("apps.members.read") ? undefined : "none" }}
            to={`/dashboard/apps/${row.id}/members`}
          >
            {t("本应用成员")}
          </Button>
        </Stack>
      )}
      <Panel title={t("基本信息")} action={<Status value={status} />}>
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: {
              xs: "minmax(0, 1fr)",
              md: "repeat(2, minmax(0, 1fr))",
            },
            gap: 3,
          }}
        >
          {props.map(([label, value]) => (
            <Box key={t(label)}>
              <Typography
                variant="caption"

                color="text.secondary"
                sx={{ display: "block" }}
              >
                {t(label)}
              </Typography>
              <Typography sx={{ mt: 0.5, overflowWrap: "anywhere" }}>
                {value || "—"}
              </Typography>
            </Box>
          ))}
        </Box>
      </Panel>
      {isApp && allowed("clients.read") && (
        <Panel
          title={t("OAuth 客户端")}
          action={
            <Button
              sx={{ display: allowed("clients.manage") ? undefined : "none" }}
              startIcon={<AddRounded />}
              onClick={() =>
                editor(
                  t("新建 OAuth 客户端"),
                  "/dashboard/clients/new",
                  clientFields,
                  {},
                  { app_id: row.id },
                )
              }
            >
              {t("添加客户端")}
            </Button>
          }
        >
          {!data.clients?.length && <Empty text={t("尚未配置客户端")} />}
          {data.clients?.map((client) => (
            <Card
              key={client.id}
              variant="outlined"
              sx={{ p: 2.5, mb: 2, boxShadow: "none" }}
            >
              <Stack
                direction="row"
                sx={{ justifyContent: "space-between", gap: 2 }}
              >
                <Box sx={{ minWidth: 0, overflowWrap: "anywhere" }}>
                  <Typography variant="subtitle1">
                    {client.name || client.identifier}
                  </Typography>
                  <Typography
                    variant="caption"

                    color="text.secondary"
                    sx={{ display: "block" }}
                  >
                    {client.identifier} · {lower(client.type)}
                  </Typography>
                </Box>
                <Status value={client.status} />
              </Stack>
              <Typography
                variant="body2"
                sx={{
                  my: 2,
                  color: "text.secondary",
                  overflowWrap: "anywhere",
                }}
              >
                {t("回调地址：")}
                {client.redirect_uris?.join(" · ") || "—"}
              </Typography>
              <Stack
                direction="row"
                sx={{ flexWrap: "wrap", alignItems: "center", gap: 1 }}
              >
                <Button
                  sx={{
                    display: allowed("clients.manage") ? undefined : "none",
                  }}
                  size="small"
                  onClick={() =>
                    editor(
                      t("编辑 OAuth 客户端"),
                      `/dashboard/clients/${client.id}/edit`,
                      clientFields
                        .filter(
                          (field) =>
                            field.name !== "identifier" &&
                            (field.name !== "secret" ||
                              allowed("clients.secret.rotate")),
                        )
                        .map((field) =>
                          client.account_sync_uri &&
                          !isSuper(data.layout) &&
                          ["scopes", "client_type"].includes(field.name)
                            ? {
                                ...field,
                                disabled: true,
                                hint: t(
                                  "账户同步已启用，请由超级管理员调整类型和 scope。",
                                ),
                              }
                            : field,
                        ),
                      {
                        name: client.name,
                        client_type: lower(client.type),
                        secret: "",
                        redirect_uris: client.redirect_uris?.join("\n"),
                        post_logout_redirect_uris:
                          client.post_logout_redirect_uris?.join("\n"),
                        scopes: client.scopes?.join(","),
                        grant_types: client.grant_types?.join(","),
                        require_pkce: client.require_pkce,
                        access_token_ttl: client.access_token_ttl_seconds,
                        refresh_token_ttl: client.refresh_token_ttl_seconds,
                        id_token_ttl: client.id_token_ttl_seconds,
                      },
                    )
                  }
                >
                  {t("编辑配置")}
                </Button>
                <Button
                  sx={{
                    display: allowed("clients.manage") ? undefined : "none",
                  }}
                  size="small"
                  onClick={() =>
                    editor(
                      t("应用注销通知"),
                      `/dashboard/clients/${client.id}/backchannel-logout`,
                      [
                        {
                          name: "backchannel_logout_uri",
                          label: t("Back-channel Logout 地址"),
                          hint: t("应用接收注销令牌的 HTTPS 地址；留空停用"),
                        },
                      ],
                      {
                        backchannel_logout_uri:
                          client.backchannel_logout_uri || "",
                      },
                    )
                  }
                >
                  {t("应用注销通知")}
                </Button>
                {isSuper(data.layout) &&
                  lower(client.type) === "confidential" && (
                    <Button
                      size="small"
                      onClick={() =>
                        editor(
                          t("账户生命周期同步"),
                          `/dashboard/clients/${client.id}/account-sync`,
                          [
                            {
                              name: "account_sync_uri",
                              label: t("账户同步地址"),
                              hint: t(
                                "应用接收签名事件的 HTTPS 地址；保存后同步现有成员，留空停用。资料按客户端 scope 提供。",
                              ),
                            },
                          ],
                          { account_sync_uri: client.account_sync_uri || "" },
                        )
                      }
                    >
                      {t("账户生命周期同步")}
                    </Button>
                  )}
                <Button
                  size="small"
                  disabled={
                    !allowed("clients.secret.rotate") ||
                    lower(client.type) === "public"
                  }
                  onClick={() =>
                    editor(
                      t("平滑轮换密钥"),
                      `/dashboard/clients/${client.id}/rotate-secret`,
                      [
                        {
                          name: "grace_seconds",
                          label: t("旧密钥保留时间"),
                          options: [
                            ["3600", t("1 小时")],
                            ["86400", t("24 小时")],
                            ["604800", t("7 天")],
                          ],
                        },
                      ],
                      { grace_seconds: "86400" },
                    )
                  }
                >
                  {t("平滑轮换密钥")}
                </Button>
                {client.previous_secret_expires_at && (
                  <>
                    <Typography variant="caption">
                      {t("旧密钥到期")}：
                      {date(client.previous_secret_expires_at)}
                    </Typography>
                    <Button
                      sx={{
                        display: allowed("clients.secret.rotate")
                          ? undefined
                          : "none",
                      }}
                      size="small"
                      onClick={() =>
                        ask(
                          t("立即停用旧密钥"),
                          `/dashboard/clients/${client.id}/retire-secret`,
                        )
                      }
                    >
                      {t("停用旧密钥")}
                    </Button>
                  </>
                )}
                <Button
                  size="small"
                  disabled={
                    !allowed("clients.secret.rotate") ||
                    lower(client.type) === "public"
                  }
                  onClick={() =>
                    ask(
                      t("重置客户端密钥"),
                      `/dashboard/clients/${client.id}/reset-secret`,
                      {},
                      t("现有密钥将立即失效，使用该密钥的应用需要更新配置。"),
                    )
                  }
                >
                  {t("紧急重置密钥")}
                </Button>
                <Button
                  sx={{
                    display: allowed("clients.manage") ? undefined : "none",
                  }}
                  size="small"
                  onClick={() =>
                    ask(
                      t("切换客户端状态"),
                      `/dashboard/clients/${client.id}/toggle`,
                    )
                  }
                >
                  {t("切换状态")}
                </Button>
              </Stack>
            </Card>
          ))}
        </Panel>
      )}
      {isUser && (
        <>
          <Panel
            title={t("应用访问权限")}
            action={
              <Button
                disabled={!data.all_apps?.length}
                startIcon={<AddRounded />}
                onClick={() =>
                  editor(t("授予应用访问权限"), `${base}/grant-app`, [
                    {
                      name: "app_id",
                      label: t("应用"),
                      required: true,
                      options: data.all_apps?.map(([id, code, name]) => [
                        id,
                        `${name} (${code})`,
                      ]),
                    },
                  ])
                }
              >
                {t("授予权限")}
              </Button>
            }
          >
            {!data.access_list?.length && <Empty text={t("尚无应用授权")} />}
            {data.access_list?.map((access) => (
              <Stack
                key={access.app_id}
                direction="row"

                sx={{
                  justifyContent: "space-between",
                  alignItems: "center",
                  py: 1.5,
                }}
              >
                <Typography variant="subtitle2">{access.app_name}</Typography>
                <Stack
                  direction="row"
                  spacing={2}
                  sx={{ alignItems: "center" }}
                >
                  <Status value={access.status} />
                  <Button
                    size="small"
                    color="error"
                    disabled={
                      !can(data.layout, "apps.members.manage", access.app_id) ||
                      lower(access.status) !== "active"
                    }
                    onClick={() =>
                      ask(
                        t("撤销应用权限"),
                        `${base}/revoke-app`,
                        { app_id: access.app_id },
                        t("撤销后，该用户与此应用相关的授权及令牌将失效。"),
                      )
                    }
                  >
                    {t("撤销权限")}
                  </Button>
                </Stack>
              </Stack>
            ))}
          </Panel>
          <Panel
            title={t("登录身份")}
            action={
              <Button
                sx={{ display: allowed("events.read") ? undefined : "none" }}
                component={RouterLink}
                to={`/dashboard/events?user_id=${data.user.id}`}
              >
                {t("查看登录记录")}
              </Button>
            }
          >
            {data.identities?.length ? (
              data.identities.map((identity) => (
                <Stack
                  key={identity.id}
                  direction="row"

                  sx={{ justifyContent: "space-between", py: 1.5 }}
                >
                  <Box>
                    <Typography variant="subtitle2">
                      {identity.provider_name}
                    </Typography>
                    <Typography
                      variant="caption"

                      color="text.secondary"
                      sx={{ display: "block" }}
                    >
                      {lower(identity.kind)}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {t("最近登录")}
                    {date(identity.last_login_at)}
                  </Typography>
                </Stack>
              ))
            ) : (
              <Empty text={t("暂无登录身份")} />
            )}
          </Panel>
        </>
      )}
      {!isApp && !isUser && superAdmin && (
        <Panel
          title={t("签名密钥")}
          action={
            <Button
              startIcon={<AddRounded />}
              onClick={() =>
                editor(t("添加签名密钥"), `${base}/keys/new`, keyFields)
              }
            >
              {t("添加密钥")}
            </Button>
          }
        >
          {data.signing_health && (
            <Alert
              severity={
                data.signing_health.healthy
                  ? data.signing_health.expiring
                    ? "warning"
                    : "success"
                  : "error"
              }
              sx={{ mb: 2 }}
            >
              {!data.signing_health.healthy
                ? t("当前签名能力异常，请检查有效期与私钥")
                : data.signing_health.expiring
                  ? t("签名正常，但密钥将在 30 天内到期，请安排轮换")
                  : t("当前签名能力正常")}
            </Alert>
          )}
          <Typography variant="body2">
            {t(
              "先添加并计划激活新密钥，旧公钥保留至安全撤销时间；撤销会停止旧令牌验签。",
            )}
          </Typography>
          {!data.keys?.length && <Empty text={t("尚未配置密钥")} />}
          {data.keys?.map((key) => (
            <Stack
              key={key.id}
              direction={{ xs: "column", sm: "row" }}

              spacing={2}
              sx={{ justifyContent: "space-between", py: 2 }}
            >
              <Box>
                <Typography variant="subtitle2">{key.kid}</Typography>
                <Typography variant="body2">
                  {t("到期时间")}：{date(key.expires_at)}
                </Typography>
                <Typography variant="body2">
                  {t("计划激活")}：{date(key.activate_at)}
                </Typography>
                <Typography variant="body2">
                  {key.active
                    ? t("先激活替代密钥后再退役")
                    : `${t("可安全撤销时间")}：${key.safe_revoke_at ? date(key.safe_revoke_at) : t("现在")}`}
                </Typography>
                <Typography
                  variant="caption"

                  color="text.secondary"
                  sx={{ display: "block" }}
                >
                  {key.algorithm} ·{" "}
                  {key.revoked_at
                    ? t("已撤销")
                    : key.active
                      ? t("已激活")
                      : t("未激活")}
                </Typography>
              </Box>
              <Stack direction="row" sx={{ flexWrap: "wrap", gap: 1 }}>
                {key.activate_at && (
                  <Button
                    onClick={() =>
                      ask(
                        t("取消轮换计划"),
                        `${base}/keys/${encodeURIComponent(key.kid)}/schedule`,
                        { activate_at: "" },
                      )
                    }
                  >
                    {t("取消轮换计划")}
                  </Button>
                )}
                <Button
                  disabled={!!key.revoked_at || key.active}
                  onClick={() =>
                    editor(
                      t("轮换计划"),
                      `${base}/keys/${encodeURIComponent(key.kid)}/schedule`,
                      [
                        {
                          name: "activate_at",
                          label: t("计划激活时间（RFC3339，带时区）"),
                          required: true,
                        },
                      ],
                      { activate_at: key.activate_at || "" },
                    )
                  }
                >
                  {t("轮换计划")}
                </Button>
                <Button
                  disabled={!!key.revoked_at || key.active}
                  onClick={() =>
                    ask(
                      t("激活密钥"),
                      `${base}/keys/${encodeURIComponent(key.kid!)}/activate`,
                    )
                  }
                >
                  {t("激活")}
                </Button>
                <Button
                  color="error"
                  disabled={
                    !!key.revoked_at ||
                    key.active ||
                    (!!key.safe_revoke_at &&
                      Date.parse(key.safe_revoke_at) > Date.now())
                  }
                  onClick={() =>
                    ask(
                      t("撤销密钥"),
                      `${base}/keys/${encodeURIComponent(key.kid!)}/revoke`,
                      {},
                      t(
                        "撤销会从公钥集移除此密钥，旧令牌将无法验签。确认已超过安全撤销时间？",
                      ),
                    )
                  }
                >
                  {t("撤销")}
                </Button>
                <Button
                  color="error"
                  disabled={!!key.revoked_at}
                  onClick={() =>
                    ask(
                      t("紧急撤销泄露密钥"),
                      `${base}/keys/${encodeURIComponent(key.kid)}/revoke`,
                      { emergency: true },
                      t(
                        "仅限密钥泄露：立即停止签名并移除公钥，所有旧令牌验签会失败，可能中断登录。确认继续？",
                      ),
                    )
                  }
                >
                  {t("紧急撤销")}
                </Button>
              </Stack>
            </Stack>
          ))}
        </Panel>
      )}
      <Panel title={t("状态与安全")}>
        {isUser ? (
          <Stack direction="row" sx={{ flexWrap: "wrap", gap: 2 }}>
            <Button
              sx={{
                display: allowed("users.status.update") ? undefined : "none",
              }}
              onClick={() =>
                editor(t("修改用户状态"), `${base}/set-status`, [
                  {
                    name: "status",
                    label: t("账户状态"),
                    options: [
                      ["active", t("启用")],
                      ["disabled", t("停用")],
                      ["locked", t("锁定")],
                    ],
                    default: lower(data.user.status),
                  },
                ])
              }
            >
              {t("修改账户状态")}
            </Button>
            <Button
              sx={{
                display: allowed("users.password.reset") ? undefined : "none",
              }}
              color="warning"
              onClick={() =>
                editor(t("重置用户密码"), `${base}/reset-password`, [
                  {
                    name: "new_password",
                    label: t("新密码"),
                    type: "password",
                    required: true,
                  },
                ])
              }
            >
              {t("重置密码并退出全部会话")}
            </Button>
          </Stack>
        ) : (
          <>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              {t("停用会影响新的登录与授权，请确认相关应用已完成迁移。")}
            </Typography>
            <Button
              color="warning"
              disabled={
                system || (isApp ? !allowed("apps.manage") : !superAdmin)
              }
              onClick={() => ask(t("切换启用状态"), `${base}/toggle`)}
            >
              {t("切换启用状态")}
            </Button>
          </>
        )}
      </Panel>
    </>
  );
}
