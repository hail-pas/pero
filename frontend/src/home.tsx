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
export function Home({ data }: { data: ViewDataMap["HomeView"] }) {
  useLocale();
  return (
    <>
      <Container maxWidth="lg" sx={{ px: { xs: 2, sm: 3 } }}>
        <Stack
          component="header"
          direction="row"
          sx={{
            justifyContent: "space-between",
            alignItems: "center",
            py: { xs: 2, md: 2.5 },
          }}
        >
          <Brand />
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
            <LanguageSwitcher />
            {data.layout ? (
              <Button
                component={RouterLink}
                to="/account/profile"
                color="inherit"
              >
                {t("个人中心")}
              </Button>
            ) : (
              <>
                <Button
                  component={RouterLink}
                  to="/account/login"
                  color="inherit"
                >
                  {t("登录")}
                </Button>
                <Button
                  component={RouterLink}
                  to="/sso/register?entry=platform"
                  variant="contained"
                  color="primary"
                >
                  {t("注册账户")}
                </Button>
              </>
            )}
          </Stack>
        </Stack>
        <Box
          component="main"
          sx={{
            position: "relative",
            display: "grid",
            gridTemplateColumns: { xs: "1fr", md: "1.15fr .85fr" },
            alignItems: "center",
            gap: { xs: 4, md: 6 },
            py: { xs: 7, sm: 9, md: 12 },
            "&::before": {
              content: '""',
              position: "absolute",
              inset: { xs: "-10% 0", md: "-20% 0 -10% -30%" },
              background:
                "radial-gradient(60% 60% at 40% 40%, rgba(24,119,242,.08), transparent 70%)",
              pointerEvents: "none",
              zIndex: -1,
            },
          }}
        >
          <Box sx={{ minWidth: 0 }}>
            <Chip
              label={t("统一身份认证平台")}
              color="primary"
              variant="outlined"
              sx={{ mb: 3, bgcolor: "rgba(255,255,255,.6)" }}
            />
            <Typography
              variant="h1"
              sx={{ fontSize: { xs: 42, sm: 52, md: 64 }, lineHeight: 1.12 }}
            >
              Pero
              <br />
              <Box component="span" sx={{ color: "primary.main" }}>
                {t("用户中心")}
              </Box>
            </Typography>
            <Typography
              color="text.secondary"
              sx={{
                mt: 3,
                mb: 4,
                maxWidth: 540,
                fontSize: { xs: 16, md: 17 },
                lineHeight: 1.9,
              }}
            >
              {t(
                "基于 OAuth 2.0 / OpenID Connect 的统一身份认证与管理服务，为你的应用提供安全、可靠、易集成的用户体系。",
              )}
            </Typography>
            <Stack direction="row" spacing={1.5} sx={{ flexWrap: "wrap" }}>
              <Button
                component={RouterLink}
                to="/account/applications"
                variant="contained"
                size="large"
                color="primary"
                endIcon={<ArrowForwardRounded />}
              >
                {t("开始使用")}
              </Button>
              {data.layout?.can_access_dashboard && (
                <Button
                  component={RouterLink}
                  to="/dashboard"
                  variant="outlined"
                  color="inherit"
                  size="large"
                >
                  {t("管理控制台")}
                </Button>
              )}
            </Stack>
            <Typography
              variant="overline"
              color="text.disabled"
              sx={{
                display: "block",
                mt: 5,
                fontSize: 11,
                letterSpacing: ".12em",
              }}
            >
              OAUTH 2.0 &nbsp; / &nbsp; OIDC &nbsp; / &nbsp; SSO &nbsp; / &nbsp;
              RUST
            </Typography>
          </Box>
          <Box
            sx={{
              display: { xs: "none", md: "grid" },
              placeItems: "center",
              minWidth: 0,
            }}
          >
            <IdentityGraphic />
          </Box>
        </Box>
        <Box component="section" sx={{ py: { xs: 6, md: 8 } }}>
          <Typography
            variant="h3"
            align="center"
            sx={{ fontSize: { xs: 24, sm: 28, md: 32 } }}
          >
            {t("让身份管理，回归简单")}
          </Typography>
          <Typography
            color="text.secondary"
            align="center"
            sx={{ mt: 1.5, mb: { xs: 4, md: 5 } }}
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
              gap: 2.5,
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
                  <Box
                    sx={{
                      display: "grid",
                      placeItems: "center",
                      width: 44,
                      height: 44,
                      borderRadius: 2,
                      bgcolor: "rgba(24,119,242,.08)",
                      color: "primary.main",
                      mb: 2.5,
                      "& svg": { fontSize: 22 },
                    }}
                  >
                    {icon}
                  </Box>
                  <Typography variant="h6" gutterBottom>
                    {typeof title === "string" ? t(title) : title}
                  </Typography>
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ lineHeight: 1.75 }}
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
            gap: 2,
            py: 4,
            borderTop: 1,
            borderColor: "divider",
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
