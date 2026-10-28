import {
  Alert,
  Box,
  Button,
  MenuItem,
  Pagination,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
} from "@mui/material";
import { useSearchParams } from "react-router-dom";
import type { ViewDataMap } from "./contracts";
import { date } from "./api";
import { Heading, Panel, type Actions } from "./shared";
import { t, useLocale } from "./i18n";

export function Notifications({
  data,
  ask,
}: { data: ViewDataMap["NotificationListView"] } & Actions) {
  useLocale();
  const [params, setParams] = useSearchParams();
  const statuses: Record<string, string> = {
    queued: t("待投递"),
    retrying: t("重试中"),
    delivered: t("网关已接收"),
    expired: t("已过期"),
    cancelled: t("已取消"),
  };
  const errors: Record<string, string> = {
    http_error: t("网关拒绝请求"),
    transport_error: t("网关连接失败"),
    timeout: t("网关请求超时"),
  };
  const kinds: Record<string, string> = {
    verify_contact: t("联系方式验证"),
    reset_password: t("密码重置"),
    mfa_enabled: t("启用双重验证"),
    mfa_changed: t("更换双重验证"),
    mfa_recovery: t("双重验证恢复"),
    new_login: t("登录成功提醒"),
    password_changed: t("密码已变更"),
    password_reset_completed: t("密码恢复已完成"),
    admin_password_reset: t("管理员重置密码"),
    contact_changed: t("联系方式已变更"),
    identity_linked: t("第三方身份已绑定"),
    identity_unlinked: t("第三方身份已解绑"),
    enrollment: t("注册与邀请"),
    enrollment_rejected: t("申请已拒绝"),
  };
  return (
    <>
      <Heading
        title={t("通知投递")}
        description={t(
          "查看近 30 天的投递记录；网关接收不代表收件人已收到。记录不含验证码、链接或完整收件地址。",
        )}
      />
      {!data.enabled && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          {t("通知网关未配置，投递已暂停。")}
        </Alert>
      )}
      <Alert
        severity={
          data.summary.overdue > 0 || data.summary.failing > 0
            ? "warning"
            : "info"
        }
        sx={{ mb: 3 }}
      >
        {t(
          "待投递 {{0}} 条，延迟超过 5 分钟 {{1}} 条，连续失败至少 3 次 {{2}} 条。",
          {
            "0": data.summary.pending,
            "1": data.summary.overdue,
            "2": data.summary.failing,
          },
        )}
      </Alert>
      <Panel
        title={t("投递记录")}
        action={
          <Stack
            direction="row"
            sx={{ alignItems: "center", flexWrap: "wrap", gap: 2 }}
          >
            <Button onClick={() => window.location.reload()}>
              {t("刷新")}
            </Button>
            <TextField
              select
              size="small"
              label={t("投递状态")}
              value={params.get("status") || ""}
              sx={{ minWidth: 160 }}
              onChange={(e) => {
                const next = new URLSearchParams(params);
                e.target.value
                  ? next.set("status", e.target.value)
                  : next.delete("status");
                next.delete("page");
                setParams(next);
              }}
            >
              <MenuItem value="">{t("全部")}</MenuItem>
              {Object.entries(statuses).map(([value, label]) => (
                <MenuItem key={value} value={value}>
                  {label}
                </MenuItem>
              ))}
            </TextField>
          </Stack>
        }
      >
        <Box sx={{ overflowX: "auto" }}>
          <Table>
            <TableHead>
              <TableRow>
                {[
                  t("时间"),
                  t("通知类型"),
                  t("收件人"),
                  t("投递状态"),
                  t("尝试次数"),
                  t("最近结果"),
                  t("操作"),
                ].map((label) => (
                  <TableCell key={label}>{label}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {data.rows.map((row) => (
                <TableRow key={row.id}>
                  <TableCell sx={{ whiteSpace: "nowrap" }}>
                    {date(row.created_at)}
                    <Box color="text.secondary">{date(row.updated_at)}</Box>
                  </TableCell>
                  <TableCell>
                    {kinds[row.kind] || row.kind}
                    <Box
                      sx={{
                        fontSize: 12,
                        color: "text.secondary",
                        overflowWrap: "anywhere",
                      }}
                    >
                      {row.id}
                    </Box>
                  </TableCell>
                  <TableCell>
                    {row.channel === "email"
                      ? t("邮箱")
                      : row.channel === "phone"
                        ? t("手机")
                        : row.channel}{" "}
                    {row.recipient}
                  </TableCell>
                  <TableCell>{statuses[row.status] || row.status}</TableCell>
                  <TableCell>{row.attempts}</TableCell>
                  <TableCell>
                    {row.last_error
                      ? errors[row.last_error] || row.last_error
                      : "—"}{" "}
                    {row.http_status ?? ""}
                  </TableCell>
                  <TableCell>
                    <Button
                      disabled={!data.enabled || !row.can_retry}
                      onClick={() =>
                        ask(
                          t("立即重试"),
                          `/dashboard/notifications/${row.id}/retry`,
                          {},
                          t("立即调度原通知重试，沿用原幂等键和有效期。"),
                        )
                      }
                    >
                      {t("立即重试")}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Box>
        {!data.rows.length && <Alert severity="info">{t("暂无记录。")}</Alert>}
      </Panel>
      {data.total_pages > 1 && (
        <Stack sx={{ mt: 3, alignItems: "flex-end" }}>
          <Pagination
            page={data.page}
            count={data.total_pages}
            onChange={(_, page) => {
              const next = new URLSearchParams(params);
              next.set("page", String(page));
              setParams(next);
            }}
          />
        </Stack>
      )}
    </>
  );
}
