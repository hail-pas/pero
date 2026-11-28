import { can, isSuper } from "./permissions";
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
  useMediaQuery,
} from "@mui/material";
import { useEffect, useState } from "react";
import { Link as RouterLink, useLocation } from "react-router-dom";
import logoUrl from "./assets/logo.png";
import type { UserLayout } from "./contracts";
import { t, useLocale } from "./i18n";
import { LanguageSwitcher } from "./language-switcher";

const sidebarWidth = 272;
const headerHeight = 72;

type NavLink = readonly [path: string, label: string, icon: React.ReactNode];

const accountGroups: readonly (readonly [string, readonly NavLink[]])[] = [
  [
    "账户",
    [
      ["/account/profile", "个人资料", <PersonOutlined />],
      ["/account/tenants", "我的空间与组织", <PeopleOutlined />],
    ],
  ],
  [
    "安全",
    [
      ["/account/security", "账户安全", <ShieldOutlined />],
      ["/account/sessions", "登录设备", <DevicesOutlined />],
      ["/account/activity", "登录记录", <HistoryOutlined />],
      ["/account/identities", "关联账号", <LinkOutlined />],
    ],
  ],
  [
    "应用",
    [
      ["/account/applications", "我的应用", <AssignmentOutlined />],
      ["/account/authorizations", "已授权应用", <VerifiedUserOutlined />],
    ],
  ],
];

const adminGroups: readonly (readonly [string, readonly NavLink[]])[] = [
  [
    "平台",
    [
      ["/dashboard/admins", "管理员", <AdminPanelSettingsOutlined />],
      ["/dashboard/apps", "应用管理", <GridViewOutlined />],
      ["/dashboard/tenants", "租户管理", <PeopleOutlined />],
      ["/dashboard/users", "用户管理", <PeopleOutlined />],
      ["/dashboard/providers", "身份提供方", <FingerprintOutlined />],
    ],
  ],
  [
    "运维",
    [
      ["/dashboard/events", "登录记录", <HistoryOutlined />],
      ["/dashboard/registration", "注册与邀请", <PersonAddAltOutlined />],
      ["/dashboard/notifications", "通知投递", <NotificationsOutlined />],
      ["/dashboard/audit", "操作审计", <FactCheckOutlined />],
    ],
  ],
];

function permitted(layout: UserLayout | undefined, path: string) {
  if (!layout?.can_access_dashboard) return false;
  if (isSuper(layout)) return true;
  if (path === "/dashboard/tenants") return false;
  if (path === "/dashboard/apps")
    return Object.values(layout.admin_access?.app_grants || {}).some((p) =>
      p.includes("apps.read"),
    );
  const permissions: Record<string, string> = {
    "/dashboard/users": "users.read",
    "/dashboard/providers": "providers.read",
    "/dashboard/events": "events.read",
    "/dashboard/notifications": "notifications.read",
    "/dashboard/audit": "audit.read",
  };
  return can(layout, permissions[path]);
}

function pageTitle(pathname: string, admin: boolean) {
  const groups = admin ? adminGroups : accountGroups;
  for (const [, links] of groups)
    for (const [path, label] of links)
      if (pathname === path || pathname.startsWith(`${path}/`)) return t(label);
  return admin ? t("管理控制台") : t("个人中心");
}

export function Brand() {
  useLocale();
  return (
    <Stack
      component={RouterLink}
      to="/"
      direction="row"
      spacing={1.25}
      sx={{
        alignItems: "center",
        color: "text.primary",
        transition: "opacity .15s ease",
        "&:hover": { opacity: 0.78 },
      }}
    >
      <Box
        component="img"
        src={logoUrl}
        alt=""
        sx={{ width: 30, height: 30 }}
      />
      <Typography
        variant="h5"
        sx={{ fontFamily: "inherit", fontWeight: 700, letterSpacing: "-.02em" }}
      >
        pero
        <Box component="span" sx={{ color: "primary.main" }}>
          .
        </Box>
      </Typography>
    </Stack>
  );
}

function NavList({
  groups,
  pathname,
  onNavigate,
}: {
  groups: readonly (readonly [string, readonly NavLink[]])[];
  pathname: string;
  onNavigate: () => void;
}) {
  useLocale();
  return (
    <List disablePadding sx={{ flex: 1, overflowY: "auto", px: 1.5 }}>
      {groups.map(([group, links]) => (
        <Box key={group} component="li" sx={{ listStyle: "none" }}>
          <Typography
            component="div"
            variant="overline"
            color="text.disabled"
            sx={{
              px: 1.25,
              mt: 2.5,
              mb: 0.75,
              fontSize: 11,
              letterSpacing: ".08em",
              lineHeight: 1.6,
            }}
          >
            {t(group)}
          </Typography>
          <List disablePadding>
            {links.map(([to, label, icon]) => {
              const selected =
                pathname === to ||
                pathname.startsWith(`${to}/`) ||
                (to === "/dashboard/apps" &&
                  pathname.startsWith("/dashboard/apps"));
              return (
                <ListItemButton
                  key={to}
                  component={RouterLink}
                  to={to}
                  onClick={onNavigate}
                  selected={selected}
                  aria-current={selected ? "page" : undefined}
                  sx={{
                    minHeight: 40,
                    px: 1.25,
                    mb: 0.25,
                    color: "text.secondary",
                    "& .MuiListItemIcon-root": { color: "text.disabled" },
                    "&:hover": {
                      bgcolor: "rgba(145,158,171,.08)",
                      color: "text.primary",
                      "& .MuiListItemIcon-root": { color: "text.secondary" },
                    },
                    "&.Mui-selected": {
                      bgcolor: "rgba(24,119,242,.08)",
                      color: "primary.main",
                      "& .MuiListItemIcon-root": { color: "primary.main" },
                      "&:hover": { bgcolor: "rgba(24,119,242,.12)" },
                    },
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 32 }}>
                    <Box
                      component="span"
                      sx={{
                        display: "inline-flex",
                        "& svg": { fontSize: 20 },
                      }}
                    >
                      {icon}
                    </Box>
                  </ListItemIcon>
                  <ListItemText
                    primary={t(label)}
                    slotProps={{
                      primary: {
                        sx: {
                          fontSize: 14,
                          fontWeight: selected ? 600 : 500,
                          lineHeight: 1.5,
                        },
                      },
                    }}
                  />
                </ListItemButton>
              );
            })}
          </List>
        </Box>
      ))}
    </List>
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
  const { pathname, key: locationKey } = useLocation();
  const desktop = useMediaQuery((theme) => theme.breakpoints.up("lg"));
  useEffect(() => {
    setOpen(false);
    setWorkspaceAnchor(null);
    setAccountAnchor(null);
  }, [locationKey, desktop]);
  const admin = pathname.startsWith("/dashboard");
  const groups = (admin ? adminGroups : accountGroups)
    .map(
      ([group, links]) =>
        [
          group,
          links.filter(([path]) => (admin ? permitted(layout, path) : true)),
        ] as const,
    )
    .filter(([, links]) => links.length > 0);
  const name = layout?.user_name || t("我的账户");
  const title = pageTitle(pathname, admin);
  const nav = (
    <Stack sx={{ height: "100%", width: "100%" }}>
      <Stack
        direction="row"
        sx={{
          alignItems: "center",
          height: headerHeight,
          px: 3,
          flexShrink: 0,
          borderBottom: 1,
          borderColor: "divider",
        }}
      >
        <Brand />
      </Stack>
      <Box sx={{ px: 2, pt: 2, pb: 0.5 }}>
        <Stack
          direction="row"
          spacing={1.5}
          component="button"
          type="button"
          onClick={(e) => setWorkspaceAnchor(e.currentTarget)}
          aria-label={t("切换工作空间")}
          aria-haspopup="menu"
          aria-expanded={!!workspaceAnchor}
          sx={{
            alignItems: "center",
            width: 1,
            p: 1.25,
            background: "transparent",
            border: 1,
            borderColor: "divider",
            textAlign: "left",
            cursor: "pointer",
            borderRadius: 1.5,
            color: "text.primary",
            font: "inherit",
            transition: "background-color .15s ease, border-color .15s ease",
            "&:hover": {
              bgcolor: "rgba(145,158,171,.04)",
              borderColor: "rgba(145,158,171,.28)",
            },
          }}
        >
          <Avatar
            src={layout?.user_avatar_url}
            sx={{
              width: 36,
              height: 36,
              bgcolor: "primary.lighter",
              color: "primary.darker",
            }}
          >
            {name.slice(0, 1)}
          </Avatar>
          <Box sx={{ minWidth: 0, flex: 1 }}>
            <Typography variant="subtitle2" noWrap>
              {name}
            </Typography>
            <Typography variant="caption" color="text.secondary" noWrap>
              {admin ? t("管理工作空间") : t("个人工作空间")}
            </Typography>
          </Box>
          <KeyboardArrowDownRounded
            sx={{ fontSize: 18, color: "text.secondary" }}
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
          {layout?.can_access_dashboard && (
            <MenuItem
              component={RouterLink}
              to="/dashboard"
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
      </Box>
      <NavList
        groups={groups}
        pathname={pathname}
        onNavigate={() => setOpen(false)}
      />
      <Stack sx={{ px: 2, py: 2, gap: 0.25, flexShrink: 0 }}>
        <Divider sx={{ mb: 1 }} />
        {layout?.can_access_dashboard && (
          <Button
            component={RouterLink}
            to={admin ? "/account/profile" : "/dashboard"}
            startIcon={admin ? <PersonOutlined /> : <DashboardOutlined />}
            color="inherit"
            onClick={() => setOpen(false)}
            sx={{ justifyContent: "flex-start", color: "text.secondary" }}
          >
            {admin ? t("返回个人中心") : t("管理控制台")}
          </Button>
        )}
        <Button
          component={RouterLink}
          to="/"
          startIcon={<HomeOutlined />}
          color="inherit"
          onClick={() => setOpen(false)}
          sx={{ justifyContent: "flex-start", color: "text.secondary" }}
        >
          {t("返回首页")}
        </Button>
        <Button
          onClick={() => {
            setOpen(false);
            onLogout();
          }}
          startIcon={<LogoutOutlined />}
          color="inherit"
          sx={{ justifyContent: "flex-start", color: "text.secondary" }}
        >
          {t("退出登录")}
        </Button>
      </Stack>
    </Stack>
  );
  return (
    <Box sx={{ display: "flex", minHeight: "100dvh", bgcolor: "background.default" }}>
      <Box
        component="a"
        href="#main-content"
        sx={{
          position: "fixed",
          top: 8,
          left: 8,
          zIndex: (theme) => theme.zIndex.tooltip + 1,
          px: 2,
          py: 1,
          borderRadius: 1,
          bgcolor: "background.paper",
          color: "text.primary",
          boxShadow: 2,
          transform: "translateY(-200%)",
          transition: "transform .15s ease",
          "&:focus-visible": { transform: "translateY(0)" },
        }}
      >
        {t("跳到主要内容")}
      </Box>
      <Box
        component="nav"
        aria-label={t("主导航")}
        sx={{ width: { lg: sidebarWidth }, flexShrink: 0 }}
      >
        <Drawer
          variant={desktop ? "permanent" : "temporary"}
          open={open}
          onClose={() => setOpen(false)}
          ModalProps={{ keepMounted: true }}
          sx={{
            "& .MuiDrawer-paper": {
              width: sidebarWidth,
              borderRight: 1,
              borderColor: "divider",
              bgcolor: "background.paper",
              overflowX: "hidden",
            },
          }}
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
            height: headerHeight,
            flexShrink: 0,
            px: { xs: 2, sm: 3, md: 4 },
            bgcolor: "rgba(255,255,255,.82)",
            backdropFilter: "blur(12px)",
            borderBottom: 1,
            borderColor: "divider",
            position: "sticky",
            top: 0,
            zIndex: (theme) => theme.zIndex.appBar,
          }}
        >
          <Stack
            direction="row"
            spacing={{ xs: 1, sm: 1.5 }}
            sx={{ alignItems: "center", minWidth: 0 }}
          >
            <IconButton
              aria-label={t("打开导航")}
              onClick={() => setOpen(true)}
              edge="start"
              sx={{ display: { lg: "none" } }}
            >
              <MenuRounded />
            </IconButton>
            <Box sx={{ minWidth: 0 }}>
              <Typography
                component="div"
                variant="caption"
                color="text.secondary"
                sx={{ display: { xs: "none", sm: "block" }, lineHeight: 1.4 }}
              >
                {admin ? t("管理工作空间") : t("个人工作空间")}
              </Typography>
              <Typography
                component="div"
                variant="subtitle2"
                noWrap
                sx={{ fontWeight: 600, lineHeight: 1.4 }}
              >
                {title}
              </Typography>
            </Box>
          </Stack>
          <Stack
            direction="row"
            spacing={{ xs: 0.5, sm: 1.5 }}
            sx={{ alignItems: "center", flexShrink: 0 }}
          >
            <LanguageSwitcher />
            <Button
              aria-label={t("账户菜单")}
              aria-haspopup="menu"
              aria-expanded={!!accountAnchor}
              onClick={(e) => setAccountAnchor(e.currentTarget)}
              color="inherit"
              sx={{
                minWidth: 0,
                p: 0.5,
                pr: { sm: 1.25 },
                color: "text.primary",
              }}
            >
              <Avatar
                sx={{
                  width: 34,
                  height: 34,
                  bgcolor: "primary.lighter",
                  color: "primary.dark",
                  fontSize: 14,
                }}
                src={layout?.user_avatar_url}
              >
                {name.slice(0, 1)}
              </Avatar>
              <Box
                sx={{
                  display: { xs: "none", sm: "block" },
                  ml: 1.25,
                  textAlign: "left",
                }}
              >
                <Typography
                  variant="caption"
                  sx={{ display: "block", fontWeight: 600, lineHeight: 1.4 }}
                >
                  {name}
                </Typography>
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{ display: "block", lineHeight: 1.4 }}
                >
                  {layout?.user_username}
                </Typography>
              </Box>
              <KeyboardArrowDownRounded
                sx={{
                  display: { xs: "none", sm: "block" },
                  fontSize: 18,
                  ml: 0.5,
                  color: "text.secondary",
                }}
              />
            </Button>
            <Menu
              anchorEl={accountAnchor}
              open={!!accountAnchor}
              onClose={() => setAccountAnchor(null)}
              slotProps={{ paper: { sx: { minWidth: 230 } } }}
            >
              <Box sx={{ px: 2, py: 1, pb: 1.25 }}>
                <Typography variant="subtitle2">{name}</Typography>
                <Typography variant="caption" color="text.secondary">
                  {layout?.user_username}
                </Typography>
              </Box>
              <Divider sx={{ mb: 0.75 }} />
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
              <Divider sx={{ my: 0.75 }} />
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
        <Box
          component="main"
          id="main-content"
          tabIndex={-1}
          sx={{
            flex: 1,
            width: "100%",
            maxWidth: 1360,
            mx: "auto",
            py: { xs: 3, md: 4 },
            px: { xs: 2, sm: 3, md: 4, xl: 5 },
            outline: "none",
          }}
        >
          {children}
        </Box>
        <Typography
          component="footer"
          variant="caption"
          color="text.disabled"
          sx={{
            display: "block",
            flexShrink: 0,
            width: "100%",
            maxWidth: 1360,
            mx: "auto",
            px: { xs: 2, sm: 3, md: 4, xl: 5 },
            py: 4,
            borderTop: { xs: 1, sm: 0 },
            borderColor: "divider",
          }}
        >
          © {new Date().getFullYear()} {t("Pero · 统一身份认证平台")}
        </Typography>
      </Box>
    </Box>
  );
}
