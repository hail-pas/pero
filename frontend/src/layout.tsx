import {
  AdminPanelSettingsOutlined,
  AssignmentOutlined,
  GridViewOutlined,
  NotificationsOutlined,
  PeopleOutlined,
  PersonAddAltOutlined,
  VerifiedUserOutlined,
  DevicesOutlined,
  HistoryOutlined,
  LinkOutlined,
  FactCheckOutlined,
  DashboardOutlined,
  FingerprintOutlined,
  HomeOutlined,
  KeyboardArrowDownRounded,
  LogoutOutlined,
  MenuRounded,
  PersonOutlined,
  ShieldOutlined,
} from "@mui/icons-material";
import {
  Avatar,
  Box,
  Button,
  Container,
  Divider,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Stack,
  Typography,
} from "@mui/material";
import { useState } from "react";
import { Link as RouterLink, useLocation } from "react-router-dom";
import type { UserLayout } from "./contracts";
import { t, useLocale } from "./i18n";
import { LanguageSwitcher } from "./language-switcher";
export function Brand() {
  useLocale();
  return (
    <Stack
      component={RouterLink}
      to="/"
      direction="row"

      spacing={1.2}
      sx={{ alignItems: "center" }}
    >
      <Box
        component="img"
        src={`${import.meta.env.BASE_URL}resources/icons/logo.svg`}
        alt=""
        sx={{ width: 30, height: 30 }}
      />
      <Typography variant="h5">
        pero
        <Box component="span" sx={{ color: "primary.main" }}>
          .
        </Box>
      </Typography>
    </Stack>
  );
}
export function Layout({
  layout,
  children,
  onLogout,
}: {
  layout?: UserLayout;
  children: React.ReactNode;
  onLogout: () => void;
}) {
  useLocale();
  const [open, setOpen] = useState(false);
  const [workspaceAnchor, setWorkspaceAnchor] = useState<HTMLElement | null>(
    null,
  );
  const [accountAnchor, setAccountAnchor] = useState<HTMLElement | null>(null);
  const { pathname } = useLocation();
  const admin = pathname.startsWith("/dashboard");
  const links = admin
    ? ([
        ["/dashboard/admins", t("管理员"), <AdminPanelSettingsOutlined />],
        ["/dashboard/apps", t("应用管理"), <GridViewOutlined />],
        ["/dashboard/users", t("用户管理"), <PeopleOutlined />],
        ["/dashboard/providers", t("身份提供方"), <FingerprintOutlined />],
        ["/dashboard/events", t("登录记录"), <HistoryOutlined />],
        ["/dashboard/registration", t("注册与邀请"), <PersonAddAltOutlined />],
        ["/dashboard/notifications", t("通知投递"), <NotificationsOutlined />],
        ["/dashboard/audit", t("操作审计"), <FactCheckOutlined />],
      ] as const)
    : ([
        ["/account/profile", t("个人资料"), <PersonOutlined />],
        ["/account/security", t("账户安全"), <ShieldOutlined />],
        ["/account/sessions", t("登录设备"), <DevicesOutlined />],
        ["/account/activity", t("登录记录"), <HistoryOutlined />],
        ["/account/applications", t("应用准入与注销"), <AssignmentOutlined />],
        ["/account/authorizations", t("已授权应用"), <VerifiedUserOutlined />],
        ["/account/identities", t("关联账号"), <LinkOutlined />],
      ] as const);
  const name = layout?.user_name || t("我的账户");
  const nav = (
    <Stack sx={{ height: "100%", p: 2.5, overflowY: "auto" }}>
      <Box sx={{ p: 1, mb: 3 }}>
        <Brand />
      </Box>
      <Stack
        direction="row"
        spacing={1.5}

        component="button"
        onClick={(e) => setWorkspaceAnchor(e.currentTarget)}
        aria-label={t("切换工作空间")}
        sx={{
          alignItems: "center",
          width: 1,
          p: 1.5,
          background: "transparent",
          border: "1px solid #e9ecef",
          textAlign: "left",
          cursor: "pointer",
          borderRadius: 1.5,
          mb: 3,
          "&:hover": { bgcolor: "#f4f6f8" },
        }}
      >
        <Avatar
          src={layout?.user_avatar_url}
          sx={{ bgcolor: "primary.light", color: "primary.darker" }}
        >
          {name.slice(0, 1)}
        </Avatar>
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="subtitle2" noWrap>
            {name}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {admin ? t("管理工作空间") : t("个人工作空间")}
          </Typography>
        </Box>
        <KeyboardArrowDownRounded
          sx={{ ml: "auto", fontSize: 18, color: "text.secondary" }}
        />
      </Stack>
      <Menu
        anchorEl={workspaceAnchor}
        open={!!workspaceAnchor}
        onClose={() => setWorkspaceAnchor(null)}
        slotProps={{ paper: { sx: { minWidth: 230 } } }}
      >
        <MenuItem
          component={RouterLink}
          to="/account/profile"
          selected={!admin}
          onClick={() => {
            setWorkspaceAnchor(null);
            setOpen(false);
          }}
        >
          {t("个人工作空间")}
        </MenuItem>
        {(admin || layout?.is_admin) && (
          <MenuItem
            component={RouterLink}
            to="/dashboard/apps"
            selected={admin}
            onClick={() => {
              setWorkspaceAnchor(null);
              setOpen(false);
            }}
          >
            {t("管理工作空间")}
          </MenuItem>
        )}
      </Menu>
      <Typography
        variant="overline"
        color="text.disabled"
        sx={{ px: 2, mb: 1 }}
      >
        {admin ? t("工作空间") : t("我的账户")}
      </Typography>
      <List>
        {links.map(([to, label, icon]) => (
          <ListItemButton
            key={to}
            component={RouterLink}
            to={to}
            onClick={() => setOpen(false)}
            selected={pathname.startsWith(to)}
            sx={{
              borderRadius: 0.75,
              mb: 0.75,
              minHeight: 48,
              "&.Mui-selected": {
                bgcolor: "rgba(24,119,242,.08)",
                color: "primary.main",
              },
            }}
          >
            <ListItemIcon sx={{ minWidth: 38, color: "inherit" }}>
              {icon}
            </ListItemIcon>
            <ListItemText
              primary={t(label)}
              slotProps={{ primary: { sx: { fontSize: 14, fontWeight: 500 } } }}
            />
          </ListItemButton>
        ))}
      </List>
      <Box sx={{ flex: 1 }} />
      {(admin || layout?.is_admin) && (
        <Button
          component={RouterLink}
          to={admin ? "/account/profile" : "/dashboard/apps"}
          startIcon={admin ? <PersonOutlined /> : <DashboardOutlined />}
        >
          {admin ? t("返回个人中心") : t("管理控制台")}
        </Button>
      )}
      <Button
        component={RouterLink}
        to="/"
        startIcon={<HomeOutlined />}
        color="inherit"
      >
        {t("返回首页")}
      </Button>
      <Divider sx={{ my: 1 }} />
      <Button onClick={onLogout} startIcon={<LogoutOutlined />} color="inherit">
        {t("退出登录")}
      </Button>
    </Stack>
  );
  return (
    <Box sx={{ display: "flex", minHeight: "100dvh" }}>
      <Box component="nav" sx={{ width: { lg: 280 }, flexShrink: 0 }}>
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: "none", lg: "block" },
            "& .MuiDrawer-paper": {
              width: 280,
              borderRight: "1px solid rgba(145,158,171,.12)",
            },
          }}
        >
          {nav}
        </Drawer>
        <Drawer
          open={open}
          onClose={() => setOpen(false)}
          sx={{ "& .MuiDrawer-paper": { width: 280 } }}
        >
          {nav}
        </Drawer>
      </Box>
      <Box
        sx={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}
      >
        <Stack
          component="header"
          direction="row"

          sx={{
            justifyContent: "space-between",
            alignItems: "center",
            height: 76,
            flexShrink: 0,
            px: { xs: 2, md: 5 },
            bgcolor: "rgba(249,250,251,.9)",
            backdropFilter: "blur(8px)",
            position: "sticky",
            top: 0,
            zIndex: 10,
          }}
        >
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
            <IconButton
              aria-label={t("打开导航")}
              onClick={() => setOpen(true)}
              sx={{ display: { lg: "none" } }}
            >
              <MenuRounded />
            </IconButton>
            <Typography variant="body2" color="text.secondary">
              {admin ? t("工作空间 / 管理控制台") : t("工作空间 / 个人中心")}
            </Typography>
          </Stack>
          <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
            <LanguageSwitcher />
            <IconButton
              aria-label={t("账户菜单")}
              onClick={(e) => setAccountAnchor(e.currentTarget)}
            >
              {" "}
              <Avatar
                sx={{
                  width: 34,
                  height: 34,
                  bgcolor: "primary.lighter",
                  color: "primary.dark",
                }}
                src={layout?.user_avatar_url}
              >
                {name.slice(0, 1)}
              </Avatar>
            </IconButton>
            <Menu
              anchorEl={accountAnchor}
              open={!!accountAnchor}
              onClose={() => setAccountAnchor(null)}
              slotProps={{ paper: { sx: { minWidth: 220 } } }}
            >
              <Box sx={{ px: 2, py: 1 }}>
                <Typography variant="subtitle2">{name}</Typography>
                <Typography variant="caption" color="text.secondary">
                  {layout?.user_username}
                </Typography>
              </Box>
              <Divider />
              <MenuItem
                component={RouterLink}
                to="/account/profile"
                onClick={() => setAccountAnchor(null)}
              >
                {t("个人资料")}
              </MenuItem>
              <MenuItem
                component={RouterLink}
                to="/account/security"
                onClick={() => setAccountAnchor(null)}
              >
                {t("账户安全")}
              </MenuItem>
              <Divider />
              <MenuItem
                component={RouterLink}
                to="/sso/select-account"
                onClick={() => setAccountAnchor(null)}
              >
                {t("切换账号")}
              </MenuItem>
              <MenuItem
                onClick={() => {
                  setAccountAnchor(null);
                  onLogout();
                }}
                sx={{ color: "error.main" }}
              >
                {t("退出登录")}
              </MenuItem>
            </Menu>
          </Stack>
        </Stack>
        <Container
          component="main"
          maxWidth="xl"
          sx={{ flex: 1, py: { xs: 3, md: 4 }, px: { xs: 2, md: 5 } }}
        >
          {children}
        </Container>
        <Typography
          component="footer"
          variant="caption"
          color="text.disabled"
          sx={{ display: "block", flexShrink: 0, px: { xs: 2, md: 5 }, py: 4 }}
        >
          © {new Date().getFullYear()} {t("Pero · 统一身份认证平台")}
        </Typography>
      </Box>
    </Box>
  );
}
