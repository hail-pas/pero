import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Divider,
  Stack,
  Typography,
} from "@mui/material";
import { Link as RouterLink, useLocation, useNavigate } from "react-router-dom";
import type { ViewEnvelope } from "./contracts";
import type { Actions } from "./shared";
import { Heading, Panel } from "./shared";
import { t, useLocale } from "./i18n";

type TenantPage = ViewEnvelope<
  | "TenantAdminView"
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
  const { pathname } = useLocation();

  if (view === "TenantAdminView") {
    return (
      <>
        <Heading
          title={t("租户管理")}
          description={t("管理组织租户的基本状态；业务权限和资源由应用自行管理。")}
        />
        <Panel title={t("组织租户")}>
          <Stack spacing={2}>
            {data.tenants.map((row) => (
              <Stack
                key={row.id}
                direction="row"
                sx={{ alignItems: "center", justifyContent: "space-between" }}
              >
                <Box>
                  <Typography sx={{ fontWeight: 600 }}>
                    {row.name} ({row.slug || "—"})
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {row.members} {t("名成员")} · {row.status}
                  </Typography>
                </Box>
                <Button
                  color={row.status === "active" ? "error" : "primary"}
                  variant="outlined"
                  onClick={() =>
                    ask(
                      t(row.status === "active" ? "停用组织" : "恢复组织"),
                      `/dashboard/tenants/${row.id}/toggle`,
                    )
                  }
                >
                  {t(row.status === "active" ? "停用" : "恢复")}
                </Button>
              </Stack>
            ))}
          </Stack>
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
                `/account/tenants/${tenant.id}/toggle`,
                {},
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
              {t("组织已停用，恢复后可以继续邀请成员。")}
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
