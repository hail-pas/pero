import { Alert, Box, Button, Divider, Pagination, Stack, Typography } from "@mui/material";
import { Link as RouterLink, useSearchParams } from "react-router-dom";
import type { ViewDataMap } from "./contracts";
import { date } from "./api";
import { Heading, MetaGrid, Panel, type Actions } from "./shared";
import { labelValue, t, useLocale } from "./i18n";

export function UserSecurity({
  data,
  editor,
}: { data: ViewDataMap["UserSecurityView"] } & Actions) {
  useLocale();
  const [params, setParams] = useSearchParams();
  const endpoint = `/dashboard/users/${data.user.id}/security`;
  function intervene(action: string, title: string, session_id?: string) {
    editor(
      title,
      endpoint,
      [
        {
          name: "reason",
          label: "处理原因（勿填写密码或恢复码）",
          required: true,
        },
      ],
      {},
      { action, session_id },
    );
  }
  return (
    <>
      <Heading
        title={t("会话与登录锁定")}
        description={data.user.username}
        back={`/dashboard/users/${data.user.id}`}
      />
      <Panel title={t("密码登录临时锁定")}>
        <Stack spacing={2}>
          <Alert severity={data.login_lock.locked ? "warning" : "info"}>
            {data.login_lock.locked
              ? t("密码登录已临时锁定，剩余 {{0}} 秒。", {
                  "0": data.login_lock.retry_after_seconds,
                })
              : t("密码登录未临时锁定。")}
            {t(" 当前失败次数：{{0}}。", {
              "0": data.login_lock.failed_attempts,
            })}
          </Alert>
          <Typography variant="body2">
            {t(
              "解除临时锁定只清除密码失败计数，不会启用被停用的账号，也不会重置请求频率限制。",
            )}
          </Typography>
          <Button
            disabled={!data.login_lock.failed_attempts}
            onClick={() => intervene("unlock", "解除临时锁定")}
          >
            {t("解除临时锁定")}
          </Button>
        </Stack>
      </Panel>
      <Panel title={t("验证器恢复")}>
        <Stack spacing={2}>
          <Alert severity="warning">
            {t(
              "仅在独立核验本人身份后生成临时恢复码。此操作会使旧恢复码和全部会话失效，保留主登录凭据和验证器。",
            )}
          </Alert>
          <Typography variant="body2">
            {data.mfa_enabled
              ? t("已启用双重验证。本人可使用原恢复码自助恢复。")
              : t("此账号未启用双重验证，无需恢复验证器。")}
          </Typography>
          <Button
            disabled={!data.can_recover}
            color="warning"
            onClick={() =>
              intervene("recover_mfa", "生成临时恢复码并退出全部会话")
            }
          >
            {t("生成临时恢复码并退出全部会话")}
          </Button>
          <Typography variant="caption">
            {t(
              "不能通过此入口恢复自己的账号。管理员账号恢复需另一位可登录的超级管理员处理。",
            )}
          </Typography>
        </Stack>
      </Panel>
      <Panel
        title={t("有效会话")}
        action={
          <Button
            color="warning"
            onClick={() => intervene("revoke_all", "退出全部会话")}
          >
            {t("退出全部会话")}
          </Button>
        }
      >
        <Stack spacing={2}>
          {!data.rows.length && <Typography>{t("暂无有效会话")}</Typography>}
          {data.rows.map((s) => (
            <Stack key={s.id} spacing={1.5} sx={{ pb: 2 }}>
              <Stack
                direction={{ xs: "column", sm: "row" }}
                spacing={1}
                sx={{ justifyContent: "space-between", alignItems: { sm: "center" } }}
              >
                <Box sx={{ minWidth: 0 }}>
                  <Typography variant="subtitle2" sx={{ overflowWrap: "anywhere" }}>
                    {s.user_agent || t("未知设备")}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {s.current
                      ? t("当前会话")
                      : s.authentication_pending
                        ? t("待完成身份验证")
                        : t("已完成身份验证")}
                  </Typography>
                </Box>
                <Button
                  size="small"
                  color="warning"
                  onClick={() => intervene("revoke_one", "退出此会话", s.id)}
                >
                  {t("退出此会话")}
                </Button>
              </Stack>
              <MetaGrid
                columns={2}
                items={[
                  [t("IP 地址"), s.ip || "—"],
                  [t("最近活动"), date(s.last_seen_at)],
                  [t("创建时间"), date(s.created_at)],
                  [t("到期时间"), date(s.expires_at)],
                ]}
              />
              {!!s.app_sessions?.length && (
                <Stack spacing={1}>
                  {s.app_sessions.map((app) => (
                    <Stack
                      key={app.id}
                      direction={{ xs: "column", sm: "row" }}
                      spacing={1}
                      sx={{
                        border: 1,
                        borderColor: "divider",
                        borderRadius: 1.5,
                        p: 1.5,
                        alignItems: { sm: "center" },
                        justifyContent: "space-between",
                      }}
                    >
                      <Typography variant="body2" sx={{ flex: 1, overflowWrap: "anywhere" }}>
                        {app.app_name} · {labelValue("最大登录设备数", app.max_sessions === 0 ? t("不限制") : app.max_sessions)}
                        {" · "}
                        {date(app.created_at)}
                      </Typography>
                      <Button
                        size="small"
                        color="warning"
                        onClick={() =>
                          intervene("revoke_app_session", "退出此应用设备", app.id)
                        }
                      >
                        {t("退出此应用设备")}
                      </Button>
                    </Stack>
                  ))}
                </Stack>
              )}
              <Divider />
            </Stack>
          ))}
        </Stack>
        <Pagination
          page={data.page}
          count={Math.max(1, data.total_pages)}
          onChange={(_, page) => {
            const next = new URLSearchParams(params);
            next.set("page", String(page));
            setParams(next);
          }}
        />
      </Panel>
      <Button
        component={RouterLink}
        to={`/dashboard/events?user_id=${data.user.id}`}
      >
        {t("查看登录记录")}
      </Button>
    </>
  );
}
