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
      />
      <Card
        sx={{
          mb: 3,
          background:
            "linear-gradient(115deg,#edf7ff 0%,#f1f0ff 68%,#e6f7f3 100%)",
          color: "text.primary",
          position: "relative",
          overflow: "hidden",
          boxShadow: "none",
          border: "1px solid rgba(145,158,171,.12)",
        }}
      >
        <FingerprintRounded
          sx={{
            position: "absolute",
            right: 40,
            top: 16,
            fontSize: 160,
            color: "primary.main",
            opacity: 0.08,
            transform: "rotate(-15deg)",
            display: { xs: "none", md: "block" },
          }}
        />
        <Stack
          direction="row"

          spacing={3}
          sx={{ alignItems: "center", p: { xs: 3, md: 4 } }}
        >
          <Avatar
            src={u.avatar_url}
            sx={{
              flexShrink: 0,
              width: 84,
              height: 84,
              bgcolor: "primary.lighter",
              color: "primary.dark",
              fontSize: 30,
              border: "4px solid white",
              boxShadow: "0 8px 16px rgba(145,158,171,.16)",
            }}
          >
            {(u.nickname || u.username).slice(0, 1)}
          </Avatar>
          <Box sx={{ minWidth: 0, overflowWrap: "anywhere" }}>
            <Typography variant="h4">{u.nickname || u.username}</Typography>
            <Typography sx={{ color: "text.secondary", mt: 1, fontSize: 14 }}>
              @{u.username} {t("· 加入于")} {date(u.created_at).slice(0, 10)}
            </Typography>
          </Box>
        </Stack>
      </Card>
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: {
            xs: "minmax(0, 1fr)",
            md: "minmax(0, 1.1fr) minmax(0, 1fr)",
          },
          gap: 3,
          alignItems: "start",
        }}
      >
        <Box sx={{ "& > :last-child": { mb: 0 } }}>
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
              sx={{ height: 6, borderRadius: 3, mb: 2.5, bgcolor: "#edf3fa" }}
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
        <Box sx={{ "& > :last-child": { mb: 0 } }}>
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
                      alignItems: "center",
                      gap: 2,
                    }}
                  >
                    <Box sx={{ minWidth: 0, overflowWrap: "anywhere" }}>
                      <Typography variant="subtitle2">{label}</Typography>
                      <Typography
                        color="text.secondary"
                        variant="body2"
                        sx={{ mt: 0.5 }}
                      >
                        {u[channel] || t("尚未绑定{{0}}", { "0": t(label) })}
                      </Typography>
                    </Box>
                    <Label color={verified ? "success" : "warning"}>
                      {verified ? t("已验证") : t("未验证")}
                    </Label>
                  </Stack>
                  <Stack direction="row" spacing={1} sx={{ mt: 1.5 }}>
                    <Button
                      size="small"
                      onClick={() =>
                        editor(
                          t("更换{{0}}", { "0": t(label) }),
                          `/account/profile/change-${channel}`,
                          [
                            {
                              name: "value",
                              label: t("新{{0}}", { "0": t(label) }),
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
                        onClick={() =>
                          ask(
                            t("发送{{0}}验证码", { "0": t(label) }),
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
                      <Button
                        size="small"
                        onClick={() =>
                          editor(
                            t("验证联系方式"),
                            "/account/profile/verify-contact",
                            [
                              {
                                name: "code",
                                label: t("验证码"),
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
                        onClick={() =>
                          ask(
                            t("取消验证"),
                            "/account/profile/cancel-contact",
                            {
                              nonce,
                            },
                          )
                        }
                      >
                        {t("取消验证")}
                      </Button>
                    </Alert>
                  )}
                </Box>
              );
            })}
          </Panel>
          <Panel title={t("登录安全")}>
            <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
              <ShieldRounded color="primary" />
              <Box sx={{ flex: 1 }}>
                <Typography variant="subtitle2">
                  {u.has_password ? t("已设置登录密码") : t("尚未设置本地密码")}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {t("定期更新密码，保护账户访问。")}
                </Typography>
              </Box>
              <Button component={RouterLink} to="/account/change-password">
                {t("管理")}
              </Button>
            </Stack>
          </Panel>
        </Box>
      </Box>
    </>
  );
}
