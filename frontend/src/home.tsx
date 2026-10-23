import { IdentityGraphic } from "./components/identity-graphic";
import { FilingLink } from "./components/filing-link";
import {
  AppsRounded,
  ArrowForwardRounded,
  FingerprintRounded,
  LockRounded,
  ShieldRounded,
} from "@mui/icons-material";
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Container,
  Stack,
  Typography,
} from "@mui/material";
import { Link as RouterLink } from "react-router-dom";
import type { ViewDataMap } from "./contracts";
import { t, useLocale } from "./i18n";
import { LanguageSwitcher } from "./language-switcher";
import { Brand } from "./layout";

import { Heading, Panel } from "./shared";
export function Home() {
  useLocale();
  return (
    <>
      <Container maxWidth="lg">
        <Stack
          component="header"
          direction="row"

          sx={{ justifyContent: "space-between", alignItems: "center", py: 3 }}
        >
          <Brand />
          <Stack direction="row" spacing={1}>
            <LanguageSwitcher />
            <Button component={RouterLink} to="/account/login" color="inherit">
              {t("登录")}
            </Button>
            <Button
              component={RouterLink}
              to="/sso/register"
              variant="contained"
              color="inherit"
            >
              {t("注册账户")}
            </Button>
          </Stack>
        </Stack>
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: { xs: "1fr", md: "1.3fr 1fr" },
            alignItems: "center",
            py: { xs: 7, md: 12 },
            gap: 6,
          }}
        >
          <Box>
            <Chip
              label={t("统一身份认证平台")}
              color="primary"
              variant="outlined"
              sx={{ mb: 3 }}
            />
            <Typography
              variant="h1"
              sx={{ fontSize: { xs: 44, md: 64 }, lineHeight: 1.15 }}
            >
              Pero
              <br />
              <Box component="span" sx={{ color: "primary.main" }}>
                User Center
              </Box>
            </Typography>
            <Typography
              color="text.secondary"
              sx={{ mt: 3, mb: 4, maxWidth: 540, lineHeight: 1.9 }}
            >
              {t(
                "基于 OAuth 2.0 / OpenID Connect 的统一身份认证与管理服务，为你的应用提供安全、可靠、易集成的用户体系。",
              )}
            </Typography>
            <Stack direction="row" spacing={2}>
              <Button
                component={RouterLink}
                to="/account/profile"
                variant="contained"
                size="large"
                color="inherit"
                endIcon={<ArrowForwardRounded />}
              >
                {t("开始使用")}
              </Button>
              <Button
                component={RouterLink}
                to="/dashboard/apps"
                variant="outlined"
                color="inherit"
                size="large"
              >
                {t("管理控制台")}
              </Button>
            </Stack>
            <Typography
              variant="overline"
              color="text.disabled"
              sx={{ display: "block", mt: 4 }}
            >
              OAUTH 2.0 &nbsp; / &nbsp; OIDC &nbsp; / &nbsp; SSO &nbsp; / &nbsp;
              RUST
            </Typography>
          </Box>
          <Box
            sx={{ display: { xs: "none", md: "grid" }, placeItems: "center" }}
          >
            <IdentityGraphic />
          </Box>
        </Box>
        <Box sx={{ py: 7 }}>
          <Typography variant="h3" align="center">
            {t("让身份管理，回归简单")}
          </Typography>
          <Typography
            color="text.secondary"
            align="center"
            sx={{ mt: 2, mb: 5 }}
          >
            {t("覆盖认证、授权、管理的完整链路")}
          </Typography>
          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: {
                xs: "1fr",
                sm: "1fr 1fr",
                md: "repeat(4,1fr)",
              },
              gap: 3,
            }}
          >
            {[
              [
                <LockRounded />,
                "OAuth 2.0 / OIDC",
                t("标准授权码流程与身份协议，支持 PKCE 和令牌刷新。"),
              ],
              [
                <FingerprintRounded />,
                t("多方式登录"),
                t("用户名、邮箱、手机号与第三方身份，统一接入。"),
              ],
              [
                <ShieldRounded />,
                t("安全可靠"),
                t("密码策略、CSRF 防护与会话撤销，守护账户访问。"),
              ],
              [
                <AppsRounded />,
                t("集中管理"),
                t("用户、应用、客户端与身份提供方，一处配置。"),
              ],
            ].map(([icon, title, description], i) => (
              <Card key={i}>
                <CardContent sx={{ p: 3 }}>
                  <Box sx={{ color: "primary.main", mb: 3 }}>{icon}</Box>
                  <Typography variant="h6" gutterBottom>
                    {typeof title === "string" ? t(title) : title}
                  </Typography>
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ lineHeight: 1.8 }}
                  >
                    {typeof description === "string"
                      ? t(description)
                      : description}
                  </Typography>
                </CardContent>
              </Card>
            ))}
          </Box>
        </Box>
        <Stack
          component="footer"
          direction={{ xs: "column", sm: "row" }}

          sx={{
            justifyContent: "space-between",
            py: 5,
            borderTop: "1px dashed #dfe3e8",
          }}
        >
          <Typography variant="body2" color="text.secondary">
            {t("Pero · 统一身份认证平台")}
          </Typography>
          <Stack
            spacing={0.5}
            sx={{ alignItems: { xs: "flex-start", sm: "flex-end" } }}
          >
            <Typography variant="caption" color="text.disabled">
              Rust + Axum / PostgreSQL / Redis
            </Typography>
            <FilingLink />
          </Stack>
        </Stack>
      </Container>
    </>
  );
}
export function AdminHome({ data }: { data: ViewDataMap["AdminHomeView"] }) {
  useLocale();
  return (
    <Container maxWidth="md" sx={{ py: 6 }}>
      <Stack
        direction="row"
        sx={{ justifyContent: "space-between", alignItems: "center" }}
      >
        <Brand />
        <LanguageSwitcher />
      </Stack>
      <Box sx={{ mt: 6 }}>
        <Heading
          title={t("欢迎，{{0}}", { "0": data.username })}
          description={t("你已通过 Pero 完成身份验证。")}
        />
        <Panel title={t("账户信息")}>
          <Typography sx={{ mb: 3 }}>
            {data.email || t("尚未绑定邮箱")}
          </Typography>
          <Stack direction="row" spacing={2}>
            <Button
              component="a"
              href={data.profile_url}
              variant="contained"
              color="inherit"
            >
              {t("管理个人资料")}
            </Button>
            <Button component="a" href={data.password_url}>
              {t("账户安全")}
            </Button>
          </Stack>
        </Panel>
        <Box component="form" method="post" action="/logout">
          <input type="hidden" name="csrf_token" value={data.csrf_token} />
          <Button type="submit" color="inherit">
            {t("退出应用")}
          </Button>
        </Box>
      </Box>
    </Container>
  );
}
