import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Divider,
  MenuItem,
  Pagination,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { Link as RouterLink, useLocation, useNavigate } from "react-router-dom";
import type { ViewEnvelope } from "./contracts";
import type { Actions } from "./shared";
import { Heading, Panel } from "./shared";
import { t, useLocale } from "./i18n";

type TenantPage = ViewEnvelope<
  | "TenantAdminView"
  | "TenantAdminDetailView"
  | "TenantListView"
  | "TenantDetailView"
  | "TenantInvitationView"
  | "TenantChoiceView"
>;

export function Tenants({
  page,
  mutate,
  ask,
  editor,
}: { page: TenantPage } & Actions) {
  useLocale();
  const { view, data } = page;
  const navigate = useNavigate();
  const { pathname, search: locationSearch } = useLocation();
  function setQuery(key: string, value: string) {
    const params = new URLSearchParams(locationSearch);
    if (value) params.set(key, value); else params.delete(key);
    if (key !== "page" && key !== "member_page") params.delete(key.startsWith("member_") ? "member_page" : "page");
    navigate(`${pathname}?${params.toString()}`);
  }


  if (view === "TenantAdminView") {
    return (
      <>
        <Heading title={t("租户管理")} description={t("统一查看组织、调整成员上限与处理所有者问题")} />
        <Stack direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ mb: 2 }}>
          <TextField size="small" label={t("搜索组织（回车）")} defaultValue={data.tenants.q}
            key={data.tenants.q} onKeyDown={e => {
              if (e.key === "Enter") setQuery("q", (e.target as HTMLInputElement).value);
            }} />
          <TextField select size="small" label={t("状态")} value={data.tenants.status}
            onChange={e => setQuery("status",e.target.value)} sx={{ minWidth: 140 }}>
            <MenuItem value="">{t("全部")}</MenuItem>
            {["active","disabled","deleted"].map(s => <MenuItem key={s} value={s}>{s}</MenuItem>)}
          </TextField>
        </Stack>
        <Panel title={t("组织租户")}>
          <Stack spacing={2}>
            {data.tenants.rows.map(row => (
              <Stack key={row.id} direction={{ xs: "column", sm: "row" }} spacing={2}
                sx={{ alignItems: { sm: "center" }, justifyContent: "space-between" }}>
                <Box>
                  <Typography sx={{ fontWeight: 600 }}>{row.name} ({row.slug || "—"})</Typography>
                  <Typography color="text.secondary" variant="body2">
                    {t("所有者")}：{row.owner_name || "—"} · {row.members}/{row.max_members} {t("名成员")} · {row.status}
                  </Typography>
                </Box>
                <Stack direction="row" spacing={1}>
                  <Button component={RouterLink} to={`/dashboard/tenants/${row.id}`}>{t("详情")}</Button>
                  {row.status !== "deleted" && <Button variant="outlined"
                    color={row.status === "active" ? "error" : "primary"}
                    onClick={() => ask(t(row.status === "active" ? "停用组织" : "恢复组织"),
                      `/dashboard/tenants/${row.id}/status`,
                      { status: row.status === "active" ? "disabled" : "active" })}>
                    {t(row.status === "active" ? "停用" : "恢复")}
                  </Button>}
                </Stack>
              </Stack>
            ))}
            {data.tenants.rows.length === 0 && <Typography color="text.secondary">{t("没有匹配的组织")}</Typography>}
          </Stack>
        </Panel>
        <Pagination count={Math.max(1, data.tenants.total_pages)} page={data.tenants.page}
          onChange={(_e, p) => setQuery("page", String(p))} sx={{ mt: 2 }} />
      </>
    );
  }

  if (view === "TenantAdminDetailView") {
    const { tenant, members, apps } = data;
    return (
      <>
        <Heading title={tenant.name} back="/dashboard/tenants"
          description={`${tenant.slug || "—"} · ${tenant.status} · ${t("所有者")}：${tenant.owner_name || "—"}`} />
        <Panel title={t("组织设置")}>
          <Stack direction={{ xs: "column", sm: "row" }} sx={{ alignItems: { sm: "center" } }} spacing={2}>
            <Typography>{t("成员")}：{tenant.members}/{tenant.max_members}</Typography>
            {tenant.status !== "deleted" && (
              <Button variant="outlined" onClick={() => editor(t("设置成员上限"),
                `/dashboard/tenants/${tenant.id}/member-limit`, [
                  { name:"max_members", label:t("成员上限"), type:"number", required:true },
                ], { max_members:String(tenant.max_members) })}>{t("修改上限")}</Button>
            )}
            {tenant.status !== "deleted" && (
              <Button color={tenant.status === "active" ? "error" : "primary"}
                onClick={() => ask(t(tenant.status === "active" ? "停用组织" : "恢复组织"),
                  `/dashboard/tenants/${tenant.id}/status`,
                  { status: tenant.status === "active" ? "disabled" : "active" })}>
                {t(tenant.status === "active" ? "停用" : "恢复")}
              </Button>
            )}
          </Stack>
          <Typography sx={{ mt: 2 }} color="text.secondary" variant="body2">
            {t("降低成员上限不会移除现有成员，达到上限后不再接受新成员。")}
          </Typography>
        </Panel>
        <Panel title={t("应用准入")}>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {t("仅控制组织是否允许进入应用，业务权限与业务数据由应用自身管理。")}
          </Typography>
          <Stack spacing={1.5}>
            {apps.map(app => (
              <Stack key={app.id} direction={{ xs:"column",sm:"row" }} sx={{ alignItems: { sm:"center" }, justifyContent:"space-between" }} spacing={1}>
                <Box><Typography>{app.name} ({app.code})</Typography>
                  <Typography variant="caption" color="text.secondary">
                    {app.organization_access === "open" ? t("允许所有组织") :
                      app.granted ? t("已开通") : t("未开通")} · {app.status}
                  </Typography></Box>
                {tenant.status !== "deleted" && app.organization_access === "restricted" &&
                  <Button variant="outlined" color={app.granted ? "error" : "primary"}
                    onClick={() => ask(t(app.granted ? "撤销应用准入" : "开通应用"),
                      `/dashboard/tenants/${tenant.id}/apps/${app.id}`,
                      {action:app.granted ? "revoke" : "grant"})}>
                    {t(app.granted ? "撤销" : "开通")}
                  </Button>}
              </Stack>
            ))}
            {apps.length === 0 && <Typography color="text.secondary">{t("当前没有组织型应用")}</Typography>}
          </Stack>
        </Panel>
        <Panel title={t("组织成员")}>
          <TextField size="small" label={t("搜索成员（回车）")} defaultValue={members.q}
            key={members.q} onKeyDown={e => {
              if (e.key === "Enter") setQuery("member_q",(e.target as HTMLInputElement).value);
            }} sx={{ mb: 2 }} />
          <Stack spacing={2}>
            {members.rows.map(m => (
              <Stack key={m.user_id} direction="row" sx={{ alignItems: "center", justifyContent: "space-between" }}>
                <Box><Typography>{m.name} ({m.username})</Typography>
                  <Typography color="text.secondary" variant="caption">{m.role}</Typography></Box>
                {tenant.status !== "deleted" && m.role !== "owner" && (
                  <Button onClick={() => ask(t("设为组织所有者"),
                    `/dashboard/tenants/${tenant.id}/owner/${m.user_id}`)}>
                    {t("设为所有者")}
                  </Button>
                )}
              </Stack>
            ))}
            {members.rows.length === 0 && <Typography color="text.secondary">{t("没有匹配的成员")}</Typography>}
          </Stack>
          <Pagination count={Math.max(1,members.total_pages)} page={members.page}
            onChange={(_e,p) => setQuery("member_page",String(p))} sx={{ mt: 2 }}/>
        </Panel>
      </>
    );
  }

  if (view === "TenantChoiceView") {
    return (
      <Box sx={{ maxWidth: 520, mx: "auto", mt: 10, p: 2 }}>
        <Card>
          <CardContent>
            <Heading
              title={t("选择工作空间")}
              description={t("本次授权将限定在选择的个人或组织空间内。")}
            />
            <Box component="form" method="post" action="/oauth2/authorize/tenant">
              <input type="hidden" name="csrf_token" value={data.csrf_token} />
              <input type="hidden" name="token" value={data.token} />
              <Stack spacing={1.5}>
                {data.choices.length === 0 ? (
                  <Typography color="text.secondary">
                    {t("当前没有可访问的工作空间。")}
                  </Typography>
                ) : (
                  data.choices.map((option) => (
                    <Button
                      fullWidth
                      key={option.id}
                      variant="outlined"
                      type="submit"
                      name="tenant_id"
                      value={option.id}
                    >
                      {option.name} · {option.kind === "personal" ? t("个人") : t("组织")}
                    </Button>
                  ))
                )}
              </Stack>
            </Box>
          </CardContent>
        </Card>
      </Box>
    );
  }

  if (view === "TenantListView") {
    return (
      <>
        <Heading
          title={t("我的空间与组织")}
          description={t("个人身份统一，个人和组织数据分别存放。")}
          action={
            <Button
              variant="contained"
              disabled={!data.creation_policy.enabled || data.creation_policy.tenant_count >= data.creation_policy.max_tenants}
              onClick={() =>
                editor(t("创建组织"), "/account/tenants", [
                  { name: "name", label: t("组织名称"), required: true },
                  { name: "slug", label: t("组织标识"), required: true },
                ])
              }
            >
              {t("创建组织")}
            </Button>
          }
        />
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {data.creation_policy.enabled
            ? `${t("组织创建额度")}：${data.creation_policy.tenant_count} / ${data.creation_policy.max_tenants}`
            : t("当前未获组织创建权限；已建立的组织仍可管理。")}
        </Typography>
        <Panel title={t("已加入的工作空间")}>
          <Stack spacing={1}>
            {data.tenants.map((space) => (
              <Button
                key={space.id}
                component={RouterLink}
                to={`/account/tenants/${space.id}`}
                variant="outlined"
                sx={{ justifyContent: "space-between", textAlign: "left" }}
              >
                {space.name} ({space.kind === "personal" ? t("个人") : t("组织")}) ·{" "}
                {space.role}
              </Button>
            ))}
          </Stack>
        </Panel>
      </>
    );
  }

  if (view === "TenantInvitationView") {
    const canAccept =
      data.verified_email &&
      data.user_email?.toLowerCase() === data.invitation.email.toLowerCase();

    return (
      <>
        <Heading title={t("加入组织")} description={data.invitation.tenant_name} />
        <Panel title={t("邀请详情")}>
          <Typography sx={{ mb: 2 }}>
            {data.invitation.email} · {data.invitation.role}
          </Typography>
          {!canAccept ? (
            <Typography color="error">
              {t("请使用与邀请邮箱一致且已验证的账号接受邀请。")}
            </Typography>
          ) : (
            <Button
              variant="contained"
              onClick={() => mutate(pathname, {}, () => navigate("/account/tenants"))}
            >
              {t("接受邀请")}
            </Button>
          )}
        </Panel>
      </>
    );
  }

  const { tenant, members, invitations, current_user_id, can_invite } = data;
  const isOrganization = tenant.kind === "organization";
  const isOwner = tenant.role === "owner";
  const canManage = isOwner || tenant.role === "admin";

  return (
    <>
      <Heading
        title={tenant.name}
        back="/account/tenants"
        description={isOrganization ? t("组织工作空间") : t("个人工作空间")}
      />
      <Panel title={t("组织资料")}>
        <Stack direction="row" spacing={2} sx={{ alignItems: "center", mb: 2 }}>
          <Chip label={tenant.role} />
          <Chip variant="outlined" label={tenant.status} />
          {isOrganization && <Chip variant="outlined" label={`${t("成员上限")}：${members.length}/${tenant.max_members}`} />}
          {tenant.slug && (
            <Typography color="text.secondary">/{tenant.slug}</Typography>
          )}
        </Stack>
        {canManage && isOrganization && (
          <Button
            variant="outlined"
            onClick={() =>
              editor(
                t("修改组织名称"),
                `/account/tenants/${tenant.id}/edit`,
                [{ name: "name", label: t("组织名称"), required: true }],
                { name: tenant.name },
              )
            }
          >
            {t("编辑组织")}
          </Button>
        )}
        {isOrganization && (
          <Button
            color="error"
            sx={{ ml: 2 }}
            onClick={() =>
              ask(
                t("退出组织"),
                `/account/tenants/${tenant.id}/leave`,
                {},
                t("退出后将不能再以此组织身份访问应用。"),
              )
            }
          >
            {t("退出组织")}
          </Button>
        )}
        {isOrganization && isOwner && (
          <Button
            sx={{ ml: 2 }}
            color="warning"
            variant="outlined"
            onClick={() =>
              ask(
                t(tenant.status === "active" ? "停用组织" : "恢复组织"),
                `/account/tenants/${tenant.id}/status`,
                { status: tenant.status === "active" ? "disabled" : "active" },
                t("组织状态更改会撤销原有租户授权令牌。"),
              )
            }
          >
            {t(tenant.status === "active" ? "停用" : "恢复")}
          </Button>
        )}
      </Panel>

      {isOrganization && (
        <Panel
          title={t("组织成员")}
          action={
            canManage ? (
              <Button
                variant="contained"
                disabled={!can_invite}
                onClick={() =>
                  editor(
                    t("邀请成员"),
                    `/account/tenants/${tenant.id}/invitations`,
                    [
                      { name: "email", label: t("成员邮箱"), type: "email", required: true },
                      {
                        name: "role",
                        label: t("治理角色"),
                        required: true,
                        options: isOwner
                          ? [
                              ["member", t("成员")],
                              ["admin", t("管理员")],
                            ]
                          : [["member", t("成员")]],
                      },
                    ],
                    { role: "member" },
                  )
                }
              >
                {t("邀请成员")}
              </Button>
            ) : undefined
          }
        >
          {!can_invite && canManage && (
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              {t("组织已停用或达到成员上限，无法继续邀请成员。")}
            </Typography>
          )}
          <Stack spacing={1.5}>
            {members.map((member) => (
              <Box key={member.user_id}>
                <Stack
                  direction={{ xs: "column", sm: "row" }}
                  sx={{
                    alignItems: { sm: "center" },
                    justifyContent: "space-between",
                  }}
                  spacing={1}
                >
                  <Box>
                    <Typography sx={{ fontWeight: 600 }}>
                      {member.name} ({member.username})
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {member.role}
                    </Typography>
                  </Box>
                  {(isOwner ||
                    (tenant.role === "admin" && member.role === "member")) && (
                    <Stack direction="row" spacing={1}>
                      {isOwner && member.role !== "owner" && (
                        <Button
                          size="small"
                          onClick={() =>
                            ask(
                              t("设为所有者"),
                              `/account/tenants/${tenant.id}/members/${member.user_id}`,
                              { action: "owner" },
                            )
                          }
                        >
                          {t("设为所有者")}
                        </Button>
                      )}
                      {isOwner && member.role !== "member" && (
                        <Button
                          size="small"
                          onClick={() =>
                            ask(
                              t("设为成员"),
                              `/account/tenants/${tenant.id}/members/${member.user_id}`,
                              { action: "member" },
                            )
                          }
                        >
                          {t("设为成员")}
                        </Button>
                      )}
                      {isOwner && member.role === "member" && (
                        <Button
                          size="small"
                          onClick={() =>
                            ask(
                              t("设为管理员"),
                              `/account/tenants/${tenant.id}/members/${member.user_id}`,
                              { action: "admin" },
                            )
                          }
                        >
                          {t("设为管理员")}
                        </Button>
                      )}
                      {member.user_id !== current_user_id && (
                        <Button
                          color="error"
                          size="small"
                          onClick={() =>
                            ask(
                              t("移除成员"),
                              `/account/tenants/${tenant.id}/members/${member.user_id}`,
                              { action: "remove" },
                            )
                          }
                        >
                          {t("移除")}
                        </Button>
                      )}
                    </Stack>
                  )}
                </Stack>
                <Divider sx={{ mt: 1 }} />
              </Box>
            ))}
          </Stack>
        </Panel>
      )}

      {isOrganization && isOwner && members.length === 1 && (
        <Panel title={t("解散组织")}>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {t("解散将立即停止该组织访问所有应用，保留历史标识供业务系统对账；此操作不可恢复。")}
          </Typography>
          <Button color="error" variant="outlined" onClick={() =>
            editor(t("确认解散组织"), `/account/tenants/${tenant.id}/delete`, [
              { name: "confirmation", label: t("输入组织标识以确认"), required: true },
            ])
          }>{t("解散组织")}</Button>
        </Panel>
      )}

      {canManage && isOrganization && (
        <Panel title={t("邀请记录")}>
          <Stack spacing={1}>
            {invitations.map((inv) => (
              <Stack
                key={inv.id}
                direction="row"
                sx={{ alignItems: "center", justifyContent: "space-between" }}
              >
                <Typography>
                  {inv.email} · {inv.role} · {inv.status}
                </Typography>
                {inv.status === "pending" && (
                  <Button
                    size="small"
                    color="error"
                    onClick={() =>
                      ask(
                        t("撤销邀请"),
                        `/account/tenants/${tenant.id}/invitations/${inv.id}`,
                      )
                    }
                  >
                    {t("撤销")}
                  </Button>
                )}
              </Stack>
            ))}
          </Stack>
        </Panel>
      )}
    </>
  );
}
