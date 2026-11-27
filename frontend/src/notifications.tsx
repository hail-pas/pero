import {
  Alert,
  Box,
  Button,
  MenuItem,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { useRevalidator, useSearchParams } from "react-router-dom";
import type { ViewDataMap } from "./contracts";
import { date } from "./api";
import { Label } from "./components/label";
import { Heading, Panel, PaginationFooter, type Actions } from "./shared";
import { t, useLocale } from "./i18n";

export function Notifications({
  data,
  ask,
}: { data: ViewDataMap["NotificationListView"] } & Actions) {
  useLocale();
  const [params, setParams] = useSearchParams();
  const revalidator = useRevalidator();
  const tones: Record<string, "success" | "info" | "warning" | "default"> = {
    queued: "info",
    retrying: "warning",
    delivered: "success",
    expired: "default",
    cancelled: "default",
  };
  const statuses: Record<string, string> = {
    queued: t("待投递"),
    retrying: t("重试中"),
    delivered: t("发送服务已接收"),
    expired: t("已过期"),
    cancelled: t("已取消"),
  };
  const errors: Record<string, string> = {
    smtp_delivery_failed: t("SMTP 投递失败"),
    notification_disabled: t("发送渠道未配置"),
    http_error: t("发送服务拒绝请求"),
    transport_error: t("发送服务连接失败"),
    timeout: t("发送请求超时"),
    invalid_payload: t("通知内容格式不正确"),
    invalid_recipient: t("收件地址无效"),
    invalid_message: t("无法生成通知内容"),
    smtp_invalid_from: t("SMTP 发件地址无效"),
    smtp_invalid_configuration: t("SMTP 配置无效"),
    smtp_not_configured: t("SMTP 未配置"),
    smtp_invalid_security: t("SMTP 加密方式无效"),
    smtp_missing_password: t("SMTP 缺少认证密码"),
    sms_invalid_configuration: t("短信服务配置无效"),
    sms_not_configured: t("短信服务未配置"),
    invalid_endpoint: t("通知回调地址无效"),
    database_error: t("无法读取发送所需的数据"),
    signing_unavailable: t("通知签名暂不可用"),
    delivery_failed: t("通知投递失败"),
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
    tenant_invitation: t("组织邀请"),
    sessions_revoked: t("登录会话已撤销"),
    "sync.requested": t("请求同步"),
    "membership.granted": t("已授予应用访问资格"),
    "membership.revoked": t("已撤销应用访问资格"),
    "account.updated": t("账户资料已更新"),
    "account.status_changed": t("账户状态已变更"),
    "account.deleted": t("账户已注销"),
    "tenant.membership.changed": t("租户成员资格已变更"),
  };
  const deliveryError = (code?: string | null) =>
    !code ? "—" : Object.hasOwn(errors, code) ? errors[code] : t("通知投递失败");
  const deliveryKind = (code: string) =>
    Object.hasOwn(kinds, code) ? kinds[code] : t("未知通知类型");
  const deliveryStatus = (code: string) =>
    Object.hasOwn(statuses, code) ? statuses[code] : t("未知状态");
  return (
    <>
      <Heading
        title={t("通知投递")}
        description={t(
          "查看近 30 天的投递记录；发送服务接收不代表收件人已收到。记录不含验证码、链接或完整收件地址。",
        )}
      />
      {!data.enabled && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          {t("邮件和短信服务未配置或配置无效，发送请求将返回 503。")}
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
            <Button
              color="inherit"
              disabled={revalidator.state !== "idle"}
              onClick={() => revalidator.revalidate()}
            >
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
                    {deliveryKind(row.kind)}
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
                        : t("未知渠道")}{" "}
                    {row.recipient}
                  </TableCell>
                  <TableCell>
                    <Label color={tones[row.status] ?? "default"}>
                      {deliveryStatus(row.status)}
                    </Label>
                  </TableCell>
                  <TableCell>{row.attempts}</TableCell>
                  <TableCell>
                    {deliveryError(row.last_error)}{" "}
                    {row.http_status ?? ""}
                  </TableCell>
                  <TableCell>
                    <Button
                      disabled={!data.enabled || !row.can_retry}
                      onClick={() =>
                        ask(
                          "立即重试",
                          `/dashboard/notifications/${row.id}/retry`,
                          {},
                          "立即调度原通知重试，沿用原幂等键和有效期。",
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
      <Panel title={t("应用注销通知（最近 100 条）")}>
        <Box sx={{ overflowX: "auto" }}>
          <Table>
            <TableHead>
              <TableRow>
                {[
                  t("时间"),
                  t("客户端"),
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
              {data.logout_rows?.map((row) => (
                <TableRow key={row.id}>
                  <TableCell>{date(row.created_at)}</TableCell>
                  <TableCell>{row.identifier}</TableCell>
                  <TableCell>
                    <Label color={tones[row.status] ?? "default"}>
                      {deliveryStatus(row.status)}
                    </Label>
                  </TableCell>
                  <TableCell>{row.attempts}</TableCell>
                  <TableCell>{deliveryError(row.last_error)}</TableCell>
                  <TableCell>
                    <Button
                      disabled={!row.can_retry}
                      onClick={() =>
                        ask(
                          "立即重试",
                          `/dashboard/logout-deliveries/${row.id}/retry`,
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
        {!data.logout_rows?.length && (
          <Typography variant="body2" color="text.secondary" sx={{ px: 3 }}>
            {t("暂无记录。")}
          </Typography>
        )}
      </Panel>
      <Panel title={t("账户同步通知（最近 100 条）")}>
        <Box sx={{ overflowX: "auto" }}>
          <Table>
            <TableHead>
              <TableRow>
                {[
                  t("时间"),
                  t("客户端"),
                  t("用户 ID"),
                  t("通知类型"),
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
              {data.sync_rows?.map((row) => (
                <TableRow key={row.id}>
                  <TableCell>{date(row.created_at)}</TableCell>
                  <TableCell>{row.identifier}</TableCell>
                  <TableCell>{row.user_id}</TableCell>
                  <TableCell>
                    {deliveryKind(row.kind)}
                    <Box color="text.secondary">{row.id}</Box>
                  </TableCell>
                  <TableCell>
                    <Label color={tones[row.status] ?? "default"}>
                      {deliveryStatus(row.status)}
                    </Label>
                  </TableCell>
                  <TableCell>{row.attempts}</TableCell>
                  <TableCell>{deliveryError(row.last_error)}</TableCell>
                  <TableCell>
                    <Button
                      disabled={!row.can_retry}
                      onClick={() =>
                        ask(
                          "立即重试",
                          `/dashboard/account-sync-deliveries/${row.id}/retry`,
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
        {!data.sync_rows?.length && (
          <Typography variant="body2" color="text.secondary" sx={{ px: 3 }}>
            {t("暂无记录。")}
          </Typography>
        )}
      </Panel>
      {data.total_pages > 1 && (
        <PaginationFooter
          page={data.page}
          totalPages={data.total_pages}
          onChange={(page) => {
            const next = new URLSearchParams(params);
            next.set("page", String(page));
            setParams(next);
          }}
        />
      )}
    </>
  );
}
