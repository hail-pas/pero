import {
  CheckCircleRounded,
  FingerprintRounded,
  RadioButtonUncheckedRounded,
  ShieldRounded,
} from "@mui/icons-material";
import {
  Alert,
  Avatar,
  Box,
  Button,
  Card,
  Divider,
  LinearProgress,
  Stack,
  Typography,
} from "@mui/material";
import { Link as RouterLink } from "react-router-dom";
import { date } from "./api";
import type { ViewDataMap } from "./contracts";
import { Label } from "./components/label";
import { FieldsForm, userFields } from "./forms";
import { t, useLocale } from "./i18n";

import { Heading, Panel, type Actions } from "./shared";
export function Profile({
  data,
  mutate,
  ask,
  editor,
}: { data: ViewDataMap["ProfileView"] } & Actions) {
  useLocale();
  const u = data.user;
  const checks = [
    ["密码保护", u.has_password],
    ["邮箱验证", u.email_verified],
    ["手机号验证", u.phone_verified],
  ] as const;
  const completed = checks.filter(([, done]) => done).length;
  return (
    <>
      <Heading
        title={t("个人资料")}
        description={t("你的身份信息与联系方式，尽在一处。")}
        action={
          <Button
            component={RouterLink}
            to="/account/security"
            color="inherit"
            variant="outlined"
          >
            {t("账户安全")}
          </Button>
        }
      />
      <Card
        sx={{
          mb: 3,
          position: "relative",
          overflow: "hidden",
          borderColor: "rgba(145,158,171,.16)",
          background:
            "linear-gradient(115deg,#eef7ff 0%,#f3f1ff 62%,#ecf8f4 100%)",
          boxShadow: "none",
        }}
      >
        <FingerprintRounded
          aria-hidden
          sx={{
            position: "absolute",
            right: 32,
            top: 8,
            fontSize: 168,
            color: "primary.main",
            opacity: 0.07,
            transform: "rotate(-15deg)",
            display: { xs: "none", md: "block" },
          }}
        />
        <Stack
          direction={{ xs: "column", sm: "row" }}
          spacing={{ xs: 2, sm: 3 }}
          sx={{
            position: "relative",
            alignItems: { xs: "flex-start", sm: "center" },
            p: { xs: 3, md: 4 },
          }}
        >
          <Avatar
            src={u.avatar_url}
            sx={{
              flexShrink: 0,
              width: { xs: 64, sm: 80 },
              height: { xs: 64, sm: 80 },
              bgcolor: "primary.lighter",
              color: "primary.dark",
              fontSize: 28,
              border: "3px solid white",
              boxShadow: "0 8px 20px rgba(145,158,171,.18)",
            }}
          >
            {(u.nickname || u.username).slice(0, 1)}
          </Avatar>
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="h4" sx={{ fontSize: { xs: 24, sm: 28 } }}>
              {u.nickname || u.username}
            </Typography>
            <Typography
              color="text.secondary"
              sx={{ mt: 0.75, fontSize: 14, overflowWrap: "anywhere" }}
            >
              @{u.username} {t("· 加入于")} {date(u.created_at, false)}
            </Typography>
          </Box>
          <Box sx={{ ml: { sm: "auto!important" }, flexShrink: 0 }}>
            <Label
              color={completed === 3 ? "success" : "info"}
              sx={{ height: 28 }}
            >
              {t("资料完成度")} {completed}/3
            </Label>
          </Box>
        </Stack>
      </Card>
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: {
            xs: "minmax(0, 1fr)",
            md: "minmax(0, 1.05fr) minmax(0, 1fr)",
          },
          gap: 3,
          alignItems: "start",
        }}
      >
        <Box sx={{ "& > :last-child": { mb: 0 }, minWidth: 0 }}>
          <Panel title={t("基本资料")}>
            <FieldsForm
              fields={userFields.filter((f) =>
                ["nickname", "avatar_url"].includes(f.name),
              )}
              initial={{ nickname: u.nickname, avatar_url: u.avatar_url }}
              submit={(values) => mutate("/account/profile", values)}
            />
          </Panel>
          <Panel
            title={t("账户设置进度")}
            action={
              <Label color={completed === 3 ? "success" : "info"}>
                {completed}/3
              </Label>
            }
          >
            <LinearProgress
              variant="determinate"
              value={(completed / 3) * 100}
              sx={{ height: 6, mb: 2.5 }}
              aria-label={t("账户设置进度")}
            />
            <Stack spacing={1.5}>
              {checks.map(([label, done]) => (
                <Stack
                  key={label}
                  direction="row"
                  spacing={1.5}
                  sx={{ alignItems: "center" }}
                >
                  {done ? (
                    <CheckCircleRounded
                      sx={{ fontSize: 19, color: "success.main" }}
                    />
                  ) : (
                    <RadioButtonUncheckedRounded
                      sx={{ fontSize: 19, color: "text.disabled" }}
                    />
                  )}
                  <Typography
                    variant="body2"
                    color={done ? "text.primary" : "text.secondary"}
                  >
                    {t(label)}
                  </Typography>
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ ml: "auto!important" }}
                  >
                    {done ? t("已完成") : t("待完善")}
                  </Typography>
                </Stack>
              ))}
            </Stack>
          </Panel>
        </Box>
        <Box sx={{ "& > :last-child": { mb: 0 }, minWidth: 0 }}>
          <Panel title={t("联系方式")}>
            {(["email", "phone"] as const).map((channel, i) => {
              const nonce = u[`pending_${channel}_nonce`],
                pending = u[`pending_${channel}_value`],
                label = channel === "email" ? t("邮箱") : t("手机"),
                verified = u[`${channel}_verified`];
              return (
                <Box key={channel}>
                  {i > 0 && <Divider sx={{ my: 3 }} />}
                  <Stack
                    direction="row"
                    sx={{
                      justifyContent: "space-between",
                      alignItems: "flex-start",
                      gap: 2,
                    }}
                  >
                    <Box sx={{ minWidth: 0 }}>
                      <Typography variant="subtitle2">{label}</Typography>
                      <Typography
                        color="text.secondary"
                        variant="body2"
                        sx={{ mt: 0.5, overflowWrap: "anywhere" }}
                      >
                        {u[channel] || t("尚未绑定{{0}}", { "0": t(label) })}
                      </Typography>
                    </Box>
                    <Label color={verified ? "success" : "warning"} sx={{ flexShrink: 0 }}>
                      {verified ? t("已验证") : t("未验证")}
                    </Label>
                  </Stack>
                  <Stack direction="row" spacing={1} sx={{ mt: 1.5, flexWrap: "wrap", gap: 1 }}>
                    <Button
                      size="small"
                      color="inherit"
                      onClick={() =>
                        editor(
                          () => t("更换{{0}}", { "0": t(label) }),
                          `/account/profile/change-${channel}`,
                          [
                            {
                              name: "value",
                              label: () => t("新{{0}}", { "0": t(label) }),
                              required: true,
                              type: channel === "email" ? "email" : "text",
                            },
                          ],
                        )
                      }
                    >
                      {t(u[channel] ? "更换{{0}}" : "绑定{{0}}", {
                        "0": t(label),
                      })}
                    </Button>
                    {u[channel] && !verified && (
                      <Button
                        size="small"
                        color="inherit"
                        onClick={() =>
                          ask(
                            () => t("发送{{0}}验证码", { "0": t(label) }),
                            `/account/profile/send-verify-${channel}`,
                          )
                        }
                      >
                        {t("发送验证码")}
                      </Button>
                    )}
                  </Stack>
                  {nonce && (
                    <Alert severity="info" sx={{ mt: 2 }}>
                      <Typography variant="body2">
                        {t("等待验证：")}
                        {pending}
                      </Typography>
                      <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap", gap: 1 }}>
                        <Button
                          size="small"
                          onClick={() =>
                            editor(
                              "验证联系方式",
                              "/account/profile/verify-contact",
                              [
                                {
                                  name: "code",
                                  label: "验证码",
                                  required: true,
                                },
                              ],
                              {},
                              { nonce },
                            )
                          }
                        >
                          {t("输入验证码")}
                        </Button>
                        <Button
                          size="small"
                          color="inherit"
                          onClick={() =>
                            ask(
                              "取消验证",
                              "/account/profile/cancel-contact",
                              {
                                nonce,
                              },
                            )
                          }
                        >
                          {t("取消验证")}
                        </Button>
                      </Stack>
                    </Alert>
                  )}
                </Box>
              );
            })}
          </Panel>
          <Panel title={t("登录安全")}>
            <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
              <Box
                sx={{
                  display: "grid",
                  placeItems: "center",
                  width: 40,
                  height: 40,
                  borderRadius: 1.5,
                  bgcolor: "rgba(24,119,242,.08)",
                  flexShrink: 0,
                }}
              >
                <ShieldRounded color="primary" sx={{ fontSize: 20 }} />
              </Box>
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Typography variant="subtitle2">
                  {u.has_password ? t("已设置登录密码") : t("尚未设置本地密码")}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {t("定期更新密码，保护账户访问。")}
                </Typography>
              </Box>
              <Button
                component={RouterLink}
                to="/account/change-password"
                size="small"
                color="inherit"
                sx={{ flexShrink: 0 }}
              >
                {t("管理")}
              </Button>
            </Stack>
          </Panel>
        </Box>
      </Box>
    </>
  );
}
