import {
  Alert,
  Box,
  Button,
  Chip,
  MenuItem,
  Pagination,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import {
  Link as RouterLink,
  useLocation,
  useSearchParams,
} from "react-router-dom";
import { FieldsForm } from "./forms";
import type { ViewDataMap, ViewEnvelope } from "./contracts";
import { date, errorText } from "./api";
import { Heading, Panel, type Actions } from "./shared";
import { t, useLocale } from "./i18n";

export type SecurityView =
  | "SessionListView"
  | "ActivityListView"
  | "AuthorizationListView"
  | "IdentityListView"
  | "AuditListView";

export function Security({
  page,
  ask,
}: { page: ViewEnvelope<SecurityView> } & Actions) {
  useLocale();
  const [params, setParams] = useSearchParams();
  const location = useLocation();
  const { view, data } = page;
  function filter(name: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(name, value);
    else next.delete(name);
    next.delete("page");
    setParams(next);
  }
  const titles = {
    SessionListView: t("登录设备"),
    ActivityListView: t("登录记录"),
    AuthorizationListView: t("已授权应用"),
    IdentityListView: t("关联账号"),
    AuditListView: t("操作审计"),
  };
  const eventNames: Record<string, string> = {
    login_success: t("登录成功"),
    login_failure: t("登录失败"),
    logout: t("退出登录"),
    pending: t("结果待确认"),
    success: t("成功"),
    failure: t("失败"),
  };
  return (
    <>
      <Heading
        title={titles[view]}
        action={
          view === "SessionListView" && (
            <Stack direction="row" sx={{ flexWrap: "wrap", gap: 1 }}>
              <Button
                onClick={() =>
                  ask(
                    t("退出其他设备"),
                    "/account/sessions/revoke",
                    { scope: "others" },
                    t("保留当前会话，退出其他设备并撤销其关联令牌。"),
                  )
                }
              >
                {t("退出其他设备")}
              </Button>
              <Button
                color="warning"
                onClick={() =>
                  ask(
                    t("退出全部设备"),
                    "/account/sessions/revoke",
                    { scope: "all" },
                    t("包括当前设备在内的所有会话将退出，你需要重新登录。"),
                  )
                }
              >
                {t("退出全部设备")}
              </Button>
            </Stack>
          )
        }
      />
      {(view === "ActivityListView" || view === "AuditListView") && (
        <Panel title={t("检索条件")}>
          <FieldsForm
            key={params.toString()}
            fields={[
              {
                name: "q",
                label:
                  view === "AuditListView" ? t("操作者用户名") : t("用户名"),
              },
              { name: "ip", label: t("IP 地址") },
              { name: "from", label: t("开始时间"), type: "datetime-local" },
              { name: "to", label: t("结束时间"), type: "datetime-local" },
              ...(view === "AuditListView"
                ? [
                    { name: "action", label: t("操作路由") },
                    { name: "target", label: t("操作目标") },
                    { name: "request_id", label: t("请求编号") },
                  ]
                : [{ name: "provider_id", label: t("身份源 ID") }]),
            ]}
            initial={Object.fromEntries(
              [
                "q",
                "ip",
                "from",
                "to",
                "action",
                "target",
                "request_id",
                "provider_id",
              ].map((k) => [
                k,
                ["from", "to"].includes(k) && params.get(k)
                  ? new Date(params.get(k)!)
                      .toLocaleString("sv-SE")
                      .replace(" ", "T")
                      .slice(0, 16)
                  : params.get(k) || "",
              ]),
            )}
            submit={async (values) => {
              const next = new URLSearchParams(params);
              next.delete("page");
              Object.entries(values).forEach(([k, v]) => {
                if (v)
                  next.set(
                    k,
                    ["from", "to"].includes(k)
                      ? new Date(String(v)).toISOString()
                      : String(v),
                  );
                else next.delete(k);
              });
              setParams(next);
            }}
            label={t("查询")}
          />
        </Panel>
      )}
      {view === "SessionListView" && (
        <>
          <Alert severity="info" sx={{ mb: 3 }}>
            {t(
              "撤销会话会同时撤销关联刷新令牌。接入应用的退出生效时间取决于其在线校验方式。",
            )}
          </Alert>
          {data.rows.map((session) => (
            <Panel
              key={session.id}
              title={t("登录会话")}
              action={
                <Stack
                  direction="row"
                  spacing={1}
                  sx={{ alignItems: "center" }}
                >
                  {session.current && (
                    <Chip size="small" color="primary" label={t("当前设备")} />
                  )}
                  {session.authentication_pending && (
                    <Chip
                      size="small"
                      color="warning"
                      label={t("待完成身份验证")}
                    />
                  )}
                  <Button
                    color="warning"
                    onClick={() =>
                      ask(
                        t("退出此设备"),
                        "/account/sessions/revoke",
                        { scope: "one", session_id: session.id },
                        t("此会话及其关联刷新令牌将失效。"),
                      )
                    }
                  >
                    {t("退出此设备")}
                  </Button>
                </Stack>
              }
            >
              <Typography
                variant="body2"
                sx={{ overflowWrap: "anywhere", mb: 1 }}
              >
                {session.user_agent || t("未知设备")}
              </Typography>
              <Typography variant="body2" sx={{ overflowWrap: "anywhere" }}>
                {t("IP 地址")}：{session.ip || "—"}
              </Typography>
              <Typography variant="body2">
                {t("登录时间")}：{date(session.created_at)}
              </Typography>
              <Typography variant="body2">
                {t("最近活动")}：{date(session.last_seen_at)}
              </Typography>
              <Typography variant="body2">
                {t("到期时间")}：{date(session.expires_at)}
              </Typography>
            </Panel>
          ))}
        </>
      )}
      {view === "ActivityListView" && (
        <Panel
          title={t("认证事件")}
          action={
            <TextField
              select
              size="small"
              label={t("事件类型")}
              value={params.get("event_type") || ""}
              onChange={(e) => filter("event_type", e.target.value)}
              sx={{ minWidth: 160 }}
            >
              <MenuItem value="">{t("全部")}</MenuItem>
              {["login_success", "login_failure", "logout"].map((value) => (
                <MenuItem key={value} value={value}>
                  {eventNames[value]}
                </MenuItem>
              ))}
            </TextField>
          }
        >
          <Box sx={{ overflowX: "auto" }}>
            <Table>
              <TableHead>
                <TableRow>
                  {[
                    t("时间"),
                    ...(location.pathname.startsWith("/dashboard")
                      ? [t("用户")]
                      : []),
                    t("事件"),
                    t("登录方式"),
                    t("IP 地址"),
                    t("设备"),
                  ].map((label) => (
                    <TableCell key={label}>{label}</TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {data.rows.map((event) => (
                  <TableRow key={event.id}>
                    <TableCell sx={{ whiteSpace: "nowrap" }}>
                      {date(event.created_at)}
                    </TableCell>
                    {location.pathname.startsWith("/dashboard") && (
                      <TableCell>
                        {event.username || event.user_id || "—"}
                      </TableCell>
                    )}
                    <TableCell>
                      {eventNames[event.event_type] || event.event_type}
                    </TableCell>
                    <TableCell>
                      {event.provider_name ||
                        (event.event_type === "logout" ? "—" : t("本地账户"))}
                    </TableCell>
                    <TableCell>{event.ip || "—"}</TableCell>
                    <TableCell sx={{ overflowWrap: "anywhere", minWidth: 160 }}>
                      {event.user_agent || "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Box>
        </Panel>
      )}
      {view === "AuthorizationListView" && (
        <>
          <Alert severity="info" sx={{ mb: 3 }}>
            {t(
              "撤销会移除该应用所有客户端的数据授权并使现有令牌失效，保留应用访问资格。下次访问需重新授权。",
            )}
          </Alert>
          {data.rows.map((grant) => (
            <Panel
              key={grant.client_id}
              title={grant.app_name}
              action={
                <Button
                  color="warning"
                  onClick={() =>
                    ask(
                      t("撤销应用授权"),
                      `/account/authorizations/${grant.app_id}/revoke`,
                      {},
                      t(
                        "该应用所有客户端的授权和关联令牌将被撤销，其他应用不受影响。",
                      ),
                    )
                  }
                >
                  {t("撤销应用授权")}
                </Button>
              }
            >
              <Typography variant="body2" sx={{ mb: 1 }}>
                {t("客户端")}：{grant.client_name}
              </Typography>
              <Stack direction="row" sx={{ flexWrap: "wrap", gap: 1, mb: 1 }}>
                {grant.scopes.map((scope) => (
                  <Chip key={scope} label={scope} size="small" />
                ))}
              </Stack>
              <Typography variant="body2" color="text.secondary">
                {t("授权时间")}：{date(grant.granted_at)}
              </Typography>
            </Panel>
          ))}
        </>
      )}
      {view === "IdentityListView" && (
        <>
          {data.error && (
            <Alert severity="error" sx={{ mb: 3 }}>
              {errorText(data.error)}
            </Alert>
          )}
          <Alert severity="info" sx={{ mb: 3 }}>
            {t("解绑会退出使用该身份登录的设备。至少保留一种可用登录方式。")}
          </Alert>
          <Panel
            title={t("本地密码")}
            action={
              <Button component={RouterLink} to="/account/change-password">
                {data.has_password ? t("修改密码") : t("设置本地密码")}
              </Button>
            }
          >
            <Typography>
              {data.has_password ? t("已设置登录密码") : t("尚未设置本地密码")}
            </Typography>
          </Panel>
          {data.rows.map((identity) => (
            <Panel
              key={identity.id}
              title={identity.provider_name}
              action={
                <Button
                  color="warning"
                  onClick={() =>
                    ask(
                      t("解绑账号"),
                      `/account/identities/${identity.id}/unlink`,
                      {},
                      t("解绑后无法再通过此第三方身份登录，相关会话也将退出。"),
                    )
                  }
                >
                  {t("解绑账号")}
                </Button>
              }
            >
              {!identity.enabled && (
                <Chip size="small" label={t("身份源已停用")} sx={{ mb: 1 }} />
              )}
              <Typography variant="body2">
                {t("最近登录")}：{date(identity.last_login_at)}
              </Typography>
            </Panel>
          ))}
          <Panel title={t("绑定其他账号")}>
            <Stack direction="row" sx={{ gap: 1, flexWrap: "wrap" }}>
              {data.providers.map((provider) => (
                <Button
                  key={provider.key}
                  variant="outlined"
                  onClick={() =>
                    ask(
                      t("绑定账号"),
                      `/account/identities/${encodeURIComponent(provider.key)}/link`,
                      {},
                      t("将前往身份提供方验证账号，并绑定到当前账户。"),
                    )
                  }
                >
                  {provider.name}
                </Button>
              ))}
            </Stack>
            {!data.providers.length && (
              <Typography color="text.secondary">
                {t("暂无可绑定的身份提供方。")}
              </Typography>
            )}
          </Panel>
        </>
      )}
      {view === "AuditListView" && (
        <>
          <Alert severity="info" sx={{ mb: 3 }}>
            {t(
              "审计记录后台写操作的操作者、目标及结果，不记录密码、密钥或表单正文。结果待确认表示请求未完成结果写入。",
            )}
          </Alert>
          <Panel
            title={t("管理操作")}
            action={
              <TextField
                select
                size="small"
                label={t("处理结果")}
                value={params.get("outcome") || ""}
                onChange={(e) => filter("outcome", e.target.value)}
                sx={{ minWidth: 160 }}
              >
                <MenuItem value="">{t("全部")}</MenuItem>
                {["success", "failure", "pending"].map((value) => (
                  <MenuItem key={value} value={value}>
                    {eventNames[value]}
                  </MenuItem>
                ))}
              </TextField>
            }
          >
            <Box sx={{ overflowX: "auto" }}>
              <Table>
                <TableHead>
                  <TableRow>
                    {[
                      t("时间"),
                      t("操作者"),
                      t("操作目标"),
                      t("处理结果"),
                      t("IP 地址"),
                      t("请求编号"),
                    ].map((label) => (
                      <TableCell key={label}>{label}</TableCell>
                    ))}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {data.rows.map((event) => (
                    <TableRow key={event.id}>
                      <TableCell sx={{ whiteSpace: "nowrap" }}>
                        {date(event.created_at)}
                      </TableCell>
                      <TableCell>{event.actor_username}</TableCell>
                      <TableCell
                        sx={{
                          whiteSpace: "normal",
                          overflowWrap: "anywhere",
                          minWidth: 240,
                          maxWidth: 360,
                        }}
                      >
                        <Button
                          component={RouterLink}
                          to={`/dashboard/audit/${event.id}`}
                        >
                          {event.target}
                        </Button>
                      </TableCell>
                      <TableCell>
                        {eventNames[event.outcome] || event.outcome}{" "}
                        {event.http_status ?? ""}
                      </TableCell>
                      <TableCell>{event.ip || "—"}</TableCell>
                      <TableCell>{event.request_id || "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Box>
          </Panel>
        </>
      )}
      {!data.rows.length && <Alert severity="info">{t("暂无记录。")}</Alert>}
      {"total_pages" in data && data.total_pages > 1 && (
        <Stack sx={{ alignItems: "flex-end", mt: 3 }}>
          <Pagination
            count={data.total_pages}
            page={data.page}
            onChange={(_, value) => {
              const next = new URLSearchParams(params);
              next.set("page", String(value));
              setParams(next);
            }}
          />
        </Stack>
      )}
    </>
  );
}

export function AuditDetail({
  data,
}: {
  data: ViewDataMap["AuditDetailView"];
}) {
  const e = data.event;
  return (
    <>
      <Heading title={t("审计详情")} back="/dashboard/audit" />
      <Panel title={t("操作记录")}>
        <Stack spacing={1}>
          {[
            [t("时间"), date(e.created_at)],
            [t("操作者"), `${e.actor_username} (${e.actor_id})`],
            [t("操作路由"), e.action],
            [t("操作目标"), e.target],
            [t("处理结果"), `${e.outcome} · ${e.http_status ?? "—"}`],
            [t("IP 地址"), e.ip],
            [t("设备"), e.user_agent],
            [t("请求编号"), e.request_id],
          ].map(([label, value]) => (
            <Typography key={label} sx={{ overflowWrap: "anywhere" }}>
              {label}：{value || "—"}
            </Typography>
          ))}
        </Stack>
      </Panel>
      <Panel title={t("配置变更")}>
        <Typography variant="body2" sx={{ mb: 2 }}>
          {t("仅展示允许记录的配置字段，不包含密码、密钥和联系方式。")}
        </Typography>
        {!Object.keys(e.details).length ? (
          <Typography>{t("暂无字段变更记录")}</Typography>
        ) : (
          <Box sx={{ overflowX: "auto" }}>
            <Table>
              <TableHead>
                <TableRow>
                  {[t("字段"), t("变更前"), t("变更后")].map((v) => (
                    <TableCell key={v}>{v}</TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {Object.entries(e.details).map(([key, v]) => (
                  <TableRow key={key}>
                    <TableCell>{key}</TableCell>
                    <TableCell
                      sx={{
                        whiteSpace: "normal",
                        overflowWrap: "anywhere",
                        maxWidth: 360,
                      }}
                    >
                      {JSON.stringify(v.before)}
                    </TableCell>
                    <TableCell
                      sx={{
                        whiteSpace: "normal",
                        overflowWrap: "anywhere",
                        maxWidth: 360,
                      }}
                    >
                      {JSON.stringify(v.after)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Box>
        )}
      </Panel>
    </>
  );
}
