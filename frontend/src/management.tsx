import { can, isSuper } from "./permissions";
import {
  AddRounded,
  MoreVertRounded,
  SearchRounded,
} from "@mui/icons-material";
import {
  Avatar,
  Box,
  Button,
  Card,
  Chip,
  IconButton,
  InputAdornment,
  Menu,
  MenuItem,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
  useMediaQuery,
} from "@mui/material";
import { useState } from "react";
import { Link as RouterLink, useLocation, useNavigate } from "react-router-dom";
import { date, lower } from "./api";
import type { ViewEnvelope, ListView, DateValue } from "./contracts";
import { t, useLocale } from "./i18n";

import {
  Empty,
  Heading,
  PaginationFooter,
  Status,
  Toolbar,
  names,
} from "./shared";
interface ManagementRow {
  id: string;
  name: string;
  description: string;
  code: string;
  protocol?: string;
  avatar_url?: string;
  email?: string | null;
  phone?: string | null;
  status: string | boolean;
  created_at: DateValue;
  editable: boolean;
}
export function ManagementList({ page }: { page: ViewEnvelope<ListView> }) {
  const { view, data } = page;
  useLocale();
  const navigate = useNavigate(),
    location = useLocation();
  const kind = view.startsWith("App")
    ? "apps"
    : view.startsWith("User")
      ? "users"
      : "providers";
  const rows: ManagementRow[] =
    view === "AppListView"
      ? data.apps.map((app) => ({
          id: app.id,
          name: app.name,
          description: app.description || "",
          code: app.code,
          status: app.status,
          created_at: app.created_at,
          editable: !app.system && can(data.layout, "apps.manage", app.id),
        }))
      : view === "UserListView"
        ? data.users.map((user) => ({
            id: user.id,
            name: user.nickname || user.username,
            description: user.username,
            code: user.username,
            avatar_url: user.avatar_url || undefined,
            email: user.email,
            phone: user.phone,
            status: user.status,
            created_at: user.created_at,
            editable:
              can(data.layout, "users.update") ||
              can(data.layout, "users.contact.update"),
          }))
        : data.providers.map((provider) => ({
            id: provider.id,
            name: provider.name,
            description: "",
            code: provider.code,
            protocol: provider.kind,
            status: provider.enabled,
            created_at: provider.created_at,
            editable: isSuper(data.layout) && lower(provider.kind) !== "local",
          }));
  const params = new URLSearchParams(location.search);
  const [query, setQuery] = useState(params.get("q") || "");
  const compact = useMediaQuery((theme) => theme.breakpoints.down("sm"));
  function filter(key: string, value: string) {
    const p = new URLSearchParams(location.search);
    value ? p.set(key, value) : p.delete(key);
    p.delete("page");
    navigate(`${location.pathname}?${p}`);
  }

  return (
    <>
      <Heading
        title={t("{{0}}管理", { "0": t(names[kind]) })}
        description={
          kind === "apps"
            ? t("连接应用，集中配置 OAuth 客户端与访问策略。")
            : kind === "users"
              ? t("管理用户资料、账户状态与应用访问权限。")
              : t("配置外部登录渠道与签名密钥。")
        }
        action={
          (kind === "users"
            ? can(data.layout, "users.create")
            : isSuper(data.layout)) && (
            <Button
              component={RouterLink}
              to={`${location.pathname}/new`}
              variant="contained"
              color="primary"
              startIcon={<AddRounded />}
            >
              {t("新建{{0}}", { "0": t(names[kind]) })}
            </Button>
          )
        }
      />
      <Card sx={{ overflow: "hidden" }}>
        <Toolbar>
          {kind !== "providers" && (
            <Box
              component="form"
              onSubmit={(e) => {
                e.preventDefault();
                filter("q", query);
              }}
              sx={{ flex: 1, minWidth: { sm: 220 } }}
            >
              <TextField
                fullWidth
                size="small"
                placeholder={t("搜索{{0}}，按 Enter 查询", {
                  "0": t(names[kind]),
                })}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                slotProps={{
                  input: {
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchRounded sx={{ color: "text.disabled" }} />
                      </InputAdornment>
                    ),
                  },
                }}
              />
            </Box>
          )}
          {kind !== "providers" && (
            <TextField
              select
              label={t("状态")}
              size="small"
              sx={{ minWidth: { xs: "100%", sm: 160 } }}
              value={params.get("status") || ""}
              onChange={(e) => filter("status", e.target.value)}
            >
              {[
                ["", t("全部状态")],
                ["active", t("已启用")],
                ["disabled", t("已停用")],
                ...(kind === "users" ? [["locked", t("已锁定")]] : []),
              ].map(([v, l]) => (
                <MenuItem key={v} value={v}>
                  {t(l)}
                </MenuItem>
              ))}
            </TextField>
          )}
        </Toolbar>
        {!compact && (
          <TableContainer sx={{ overflowX: "auto" }}>
          <Table sx={{ minWidth: 640 }}>
            <TableHead>
              <TableRow>
                <TableCell>{t("名称")}</TableCell>
                <TableCell>
                  {kind === "users"
                    ? t("联系方式")
                    : kind === "providers"
                      ? t("标识 / 协议")
                      : t("应用标识")}
                </TableCell>
                <TableCell>{t("状态")}</TableCell>
                <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                  {t("创建时间")}
                </TableCell>
                <TableCell align="right">{t("操作")}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((row) => (
                <TableRow key={row.id} hover>
                  <TableCell>
                    <Stack
                      direction="row"
                      spacing={1.5}
                      sx={{ alignItems: "center", minWidth: 0 }}
                    >
                      <Avatar
                        variant={kind === "users" ? "circular" : "rounded"}
                        src={row.avatar_url}
                        sx={{
                          width: 36,
                          height: 36,
                          bgcolor: "primary.lighter",
                          color: "primary.dark",
                          fontSize: 14,
                        }}
                      >
                        {(row.name || "?").slice(0, 1)}
                      </Avatar>
                      <Box sx={{ minWidth: 0 }}>
                        <Typography
                          component={RouterLink}
                          to={`/dashboard/${kind}/${row.id}`}
                          variant="subtitle2"
                          sx={{
                            display: "block",
                            overflowWrap: "anywhere",
                            "&:hover": { color: "primary.main" },
                          }}
                        >
                          {row.name}
                        </Typography>
                        {row.description && (
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{ display: "block", overflowWrap: "anywhere" }}
                          >
                            {row.description.slice(0, 45)}
                          </Typography>
                        )}
                      </Box>
                    </Stack>
                  </TableCell>
                  <TableCell>
                    {kind === "users" ? (
                      <>
                        <Typography variant="body2" sx={{ overflowWrap: "anywhere" }}>
                          {row.email || t("未绑定邮箱")}
                        </Typography>
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{ display: "block" }}
                        >
                          {row.phone || t("未绑定手机")}
                        </Typography>
                      </>
                    ) : (
                      <Stack
                        direction="row"
                        spacing={1}
                        sx={{ alignItems: "center", flexWrap: "wrap", gap: 1 }}
                      >
                        <Typography
                          variant="body2"
                          sx={{ overflowWrap: "anywhere" }}
                        >
                          {row.code}
                        </Typography>
                        {row.protocol && (
                          <Chip
                            size="small"
                            variant="outlined"
                            label={lower(row.protocol)}
                          />
                        )}
                      </Stack>
                    )}
                  </TableCell>
                  <TableCell>
                    <Status value={row.status} />
                  </TableCell>
                  <TableCell
                    sx={{
                      display: { xs: "none", md: "table-cell" },
                      color: "text.secondary",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {date(row.created_at)}
                  </TableCell>
                  <TableCell align="right">
                    <RowActions row={row} kind={kind} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          </TableContainer>
        )}
        {compact && (
          <Box>
          {rows.map((row) => (
            <Box
              key={row.id}
              sx={{
                px: 2.5,
                py: 2,
                borderTop: 1,
                borderColor: "divider",
                "&:first-of-type": { borderTop: 0 },
              }}
            >
              <Stack direction="row" spacing={1.5} sx={{ alignItems: "flex-start" }}>
                <Avatar
                  variant={kind === "users" ? "circular" : "rounded"}
                  src={row.avatar_url}
                  sx={{
                    width: 36,
                    height: 36,
                    bgcolor: "primary.lighter",
                    color: "primary.dark",
                    fontSize: 14,
                    flexShrink: 0,
                  }}
                >
                  {(row.name || "?").slice(0, 1)}
                </Avatar>
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Stack
                    direction="row"
                    spacing={1}
                    sx={{ justifyContent: "space-between", alignItems: "flex-start" }}
                  >
                    <Box sx={{ minWidth: 0 }}>
                      <Typography
                        component={RouterLink}
                        to={`/dashboard/${kind}/${row.id}`}
                        variant="subtitle2"
                        sx={{ display: "block", overflowWrap: "anywhere" }}
                      >
                        {row.name}
                      </Typography>
                      {row.description && (
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{ display: "block", overflowWrap: "anywhere" }}
                        >
                          {row.description.slice(0, 45)}
                        </Typography>
                      )}
                    </Box>
                    <RowActions row={row} kind={kind} />
                  </Stack>
                  <Stack
                    direction="row"
                    spacing={1}
                    sx={{ alignItems: "center", flexWrap: "wrap", gap: 1, mt: 1 }}
                  >
                    {kind === "users" ? (
                      <Typography variant="body2" color="text.secondary">
                        {row.email || t("未绑定邮箱")}
                      </Typography>
                    ) : (
                      <>
                        <Typography
                          variant="body2"
                          color="text.secondary"
                          sx={{ overflowWrap: "anywhere" }}
                        >
                          {row.code}
                        </Typography>
                        {row.protocol && (
                          <Chip
                            size="small"
                            variant="outlined"
                            label={lower(row.protocol)}
                          />
                        )}
                      </>
                    )}
                    <Status value={row.status} />
                  </Stack>
                  <Typography
                    variant="caption"
                    color="text.disabled"
                    sx={{ display: "block", mt: 0.75 }}
                  >
                    {date(row.created_at)}
                  </Typography>
                </Box>
              </Stack>
            </Box>
          ))}
          </Box>
        )}
        {!rows.length && <Empty />}
        <PaginationFooter
          page={data.page || 1}
          totalPages={data.total_pages || 1}
          count={rows.length}
          onChange={(pageNumber) => {
            params.set("page", String(pageNumber));
            navigate(`${location.pathname}?${params}`);
          }}
        />
      </Card>
    </>
  );
}

function RowActions({ row, kind }: { row: ManagementRow; kind: string }) {
  useLocale();
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const base = `/dashboard/${kind}/${row.id}`;
  return (
    <>
      <IconButton
        aria-label={t("管理{{0}}", { "0": row.name })}
        onClick={(e) => setAnchor(e.currentTarget)}
      >
        <MoreVertRounded />
      </IconButton>
      <Menu
        anchorEl={anchor}
        open={!!anchor}
        onClose={() => setAnchor(null)}
        slotProps={{ paper: { sx: { minWidth: 160 } } }}
      >
        <MenuItem
          component={RouterLink}
          to={base}
          onClick={() => setAnchor(null)}
        >
          {t("查看详情")}
        </MenuItem>
        <MenuItem
          disabled={!row.editable}
          component={RouterLink}
          to={`${base}/edit`}
          onClick={() => setAnchor(null)}
        >
          {t("编辑资料")}
        </MenuItem>
      </Menu>
    </>
  );
}
