import { useState } from "react";
import { Alert, Button, Stack, Typography, Pagination } from "@mui/material";
import { Link as RouterLink, useSearchParams } from "react-router-dom";
import { FieldsForm } from "./forms";
import { Heading, Panel, type Actions } from "./shared";
import { date } from "./api";
import type { ProgressList, ViewDataMap } from "./contracts";
import { t } from "./i18n";

function admissionStatus(status: string) {
  const labels: Record<string, string> = {
    pending_verification: t("待验证邮箱"),
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
  const [failure, setFailure] = useState("");
  return (
    <>
      {failure && <Alert severity="error">{failure}</Alert>}
      <Heading
        title={t("注册与应用准入")}
        description={
          data.app
            ? t("完成此应用的准入要求后获得访问资格。")
            : t("验证邮箱并完成账户注册。")
        }
      />
      <Button component={RouterLink} to="/sso/login" sx={{ mb: 2 }}>
        {t("返回登录")}
      </Button>
      <Panel title={t("注册进度")}>
        {["completed", "rejected", "revoked", "expired"].includes(
          data.status,
        ) ? (
          <Stack spacing={2}>
            <Alert severity={data.status === "completed" ? "success" : "info"}>
              {admissionStatus(data.status)}
            </Alert>
            {data.reason && <Typography>{data.reason}</Typography>}
            <Button
              onClick={() =>
                mutate("/sso/register", { action: "reset" }).catch((e) =>
                  setFailure(e.message),
                )
              }
            >
              {t("退出本次注册流程")}
            </Button>
          </Stack>
        ) : data.mode === "closed" ? (
          <Alert severity="info">{t("注册已关闭")}</Alert>
        ) : data.status ? (
          <Stack spacing={3}>
            <Typography>
              {data.email}
              {data.app_name && ` · ${data.app_name}`}
            </Typography>
            {data.status === "pending_verification" && (
              <>
                <Alert severity="info">
                  {t("请确认验证此邮箱。邀请仅授予邮件所指定的应用资格。")}
                </Alert>
                <Button
                  onClick={() =>
                    mutate("/sso/register", { action: "verify" }).catch((e) =>
                      setFailure(e.message),
                    )
                  }
                >
                  {t("确认邮箱并继续")}
                </Button>
              </>
            )}
            {data.status === "pending_approval" && (
              <Alert severity="info">
                {t("邮箱已验证，等待管理员审批。审批后将收到邮件。")}
              </Alert>
            )}
            {data.status === "ready" && (
              <>
                <Alert severity="info">
                  {t(
                    "已有账户请先登录，再返回此页面确认加入。新用户请设置用户名和凭据。",
                  )}
                </Alert>
                <Button
                  component={RouterLink}
                  to="/account/login?redirect=%2Fsso%2Fregister"
                >
                  {data.social ? t("重新验证第三方身份") : t("登录已有账户")}
                </Button>
                <FieldsForm
                  fields={[
                    { name: "username", label: t("用户名") },
                    ...(!data.social
                      ? [
                          {
                            name: "password",
                            label: t("密码"),
                            type: "password",
                          },
                        ]
                      : []),
                  ]}
                  submit={(v) =>
                    mutate("/sso/register", { ...v, action: "finalize" })
                  }
                  label={t("完成注册或确认加入")}
                />
                {data.social && (
                  <Alert severity="info">
                    {t(
                      "第三方认证证明十分钟有效；跨设备打开邮件时，请先重新登录原身份源。",
                    )}
                  </Alert>
                )}
              </>
            )}
            <Button
              onClick={() =>
                mutate("/sso/register", { action: "reset" }).catch((e) =>
                  setFailure(e.message),
                )
              }
            >
              {t("退出本次注册流程")}
            </Button>
          </Stack>
        ) : data.sent ? (
          <Alert severity="success">
            {t("申请已排队，请检查邮件并继续。")}
          </Alert>
        ) : data.mode === "invite_only" ? (
          <Alert severity="info">
            {t("仅限邀请注册，请联系管理员获取邀请。")}
          </Alert>
        ) : (
          <FieldsForm
            fields={[
              {
                name: "email",
                label: t("邮箱"),
                type: "email",
                required: true,
              },
            ]}
            submit={(v) => mutate("/sso/register", { ...v, app: data.app })}
            label={t("发送验证邮件")}
          />
        )}
      </Panel>
    </>
  );
}
export function EnrollmentAdmin({
  data,
  mutate,
  ask,
  editor,
}: { data: ViewDataMap["EnrollmentAdminView"] } & Actions) {
  const p = data.policy;
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
      <Panel title={t("准入策略")}>
        <FieldsForm
          key={`${p.app_id}-${p.version}`}
          fields={[
            ...(p.app_id
              ? [
                  {
                    name: "inherit",
                    label: t("继承平台默认策略"),
                    type: "checkbox",
                  },
                ]
              : []),
            {
              name: "mode",
              label: t("注册模式"),
              options: [
                ["closed", t("关闭")],
                ["invite_only", t("仅邀请")],
                ["self_service", t("自助注册")],
              ],
            },
            {
              name: "domains",
              label: t("允许的邮箱域名"),
              hint: t("逗号分隔，空表示不限制；精确匹配域名。"),
            },
            {
              name: "approval_required",
              label: t("自助准入需要审批"),
              type: "checkbox",
            },
            ...(!p.app_id
              ? [
                  {
                    name: "emergency_stop",
                    label: t("紧急停止所有注册及邀请接受"),
                    type: "checkbox",
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
      <Panel title={t("发送邀请")}>
        <FieldsForm
          fields={[
            { name: "email", label: t("邮箱"), type: "email", required: true },
            {
              name: "domain_exception",
              label: t("允许此邀请超出域名限制"),
              type: "checkbox",
            },
            { name: "reason", label: t("邀请说明或例外理由") },
          ]}
          submit={(v) =>
            mutate("/dashboard/invitations", { ...v, app: p.app_id })
          }
          label={t("发送邀请")}
        />
      </Panel>
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
  const [failure, setFailure] = useState("");
  return (
    <>
      {failure && <Alert severity="error">{failure}</Alert>}
      <Heading
        title={t("应用准入与注销")}
        description={t(
          "退出应用会撤销该应用访问资格；注销账户会移除个人资料并退出所有会话。",
        )}
      />
      {data.progress && (
        <Progress data={data.progress} actions={{ mutate, ask, editor }} />
      )}
      <Panel title={t("应用访问资格")}>
        <Stack spacing={2}>
          {data.rows.map((r) => (
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
              </Typography>
              {r.status === "active" ? (
                <Button
                  color="error"
                  onClick={() =>
                    ask(t("退出应用"), `/account/applications/${r.id}`, {
                      action: "leave",
                    })
                  }
                >
                  {t("退出应用")}
                </Button>
              ) : r.status === "disabled" ? (
                <Typography>{t("请联系管理员重新授权")}</Typography>
              ) : (
                <Button
                  onClick={() =>
                    mutate(`/account/applications/${r.id}`, {
                      action: "join",
                    }).catch((e) => setFailure(e.message))
                  }
                >
                  {t("申请加入（邮件验证）")}
                </Button>
              )}
            </Stack>
          ))}
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
              t("永久注销账户"),
              "/account/close",
              v,
              t("确认删除个人资料并撤销全部访问资格？"),
            );
            return Promise.resolve();
          }}
          label={t("注销账户")}
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
  const [failure, setFailure] = useState("");
  const update = (values: Record<string, unknown>) => {
    const next = new URLSearchParams(params);
    next.delete("page");
    Object.entries(values).forEach(([k, v]) =>
      typeof v === "boolean" || v ? next.set(k, String(v)) : next.delete(k),
    );
    setParams(next);
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
              {r.email} · {r.app_name || t("平台账户")} ·{" "}
              {r.invitation ? t("邀请") : t("申请")} ·{" "}
              {admissionStatus(r.status)}
            </Typography>
            <Typography variant="caption">
              {date(r.created_at)} · {t("到期时间")}：{date(r.expires_at)}
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
                        t("批准申请"),
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
                        t("拒绝原因"),
                        `/dashboard/enrollments/${r.id}`,
                        [
                          {
                            name: "reason",
                            label: t("拒绝原因"),
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
                      onClick={() =>
                        actions
                          .mutate(`/account/enrollments/${r.id}`, {
                            action: "continue",
                          })
                          .catch((e) => setFailure(e.message))
                      }
                    >
                      {t("继续办理")}
                    </Button>
                  )}
                  <Button
                    onClick={() =>
                      actions.ask(
                        t("重发邮件"),
                        `${admin ? "/dashboard" : "/account"}/enrollments/${r.id}`,
                        { action: "resend" },
                      )
                    }
                  >
                    {t("重发")}
                  </Button>
                  <Button
                    color="warning"
                    onClick={() =>
                      actions.ask(
                        admin ? t("撤销流程") : t("撤回申请"),
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
            setParams(next);
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
}: { data: ViewDataMap["AppMembersView"] } & Actions) {
  const [params, setParams] = useSearchParams();
  const endpoint = `/dashboard/apps/${data.app_id}/members`;
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
            setParams(next);
            return Promise.resolve();
          }}
          label={t("查询")}
        />
      </Panel>
      {!data.system && (
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
              {!data.system && (
                <Button
                  onClick={() =>
                    ask(
                      r.status === "active"
                        ? t("撤销应用访问")
                        : t("授予访问资格"),
                      endpoint,
                      {
                        action: r.status === "active" ? "revoke" : "grant",
                        user_id: r.user_id,
                        username: r.username,
                      },
                    )
                  }
                >
                  {r.status === "active" ? t("撤销") : t("启用")}
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
              setParams(next);
            }}
          />
        </Stack>
      </Panel>
    </>
  );
}
