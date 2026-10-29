import { Brand } from "./layout";
import { useEffect, useRef, useState } from "react";
import { AdminPermissions } from "./admin-permissions";
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Chip,
  MenuItem,
  Pagination,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import {
  useLocation,
  useSearchParams,
  Link as RouterLink,
} from "react-router-dom";
import { FieldsForm } from "./forms";
import { Empty, Heading, Panel, type Actions } from "./shared";
import type { ViewDataMap } from "./contracts";
import { t, useLocale } from "./i18n";
import { errorText } from "./api";
export function SecurityCenter({
  data: d,
  mutate,
}: { data: ViewDataMap["SecurityView"] } & Pick<Actions, "mutate">) {
  useLocale();
  const { pathname } = useLocation();
  const [busy, setBusy] = useState(false);
  const errorRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (d.error) errorRef.current?.focus();
  }, [d.error]);
  const reauth = pathname === "/account/reauth";
  const authenticationPending = d.pending || d.recovery;
  const standalone = authenticationPending || pathname === "/sso/mfa";
  const submit = (
    action: string,
    values: Record<string, string | boolean | number | null | undefined> = {},
  ) => mutate(pathname, { ...values, action, redirect: d.redirect });
  return (
    <Box
      component={standalone ? "main" : "div"}
      sx={
        standalone
          ? {
              minHeight: "100vh",
              bgcolor: "background.neutral",
              display: "grid",
              placeItems: "center",
              p: { xs: 2, sm: 4 },
            }
          : { maxWidth: 720, mx: "auto" }
      }
    >
      <Box
        sx={
          standalone
            ? {
                width: "100%",
                maxWidth: 480,
                bgcolor: "background.paper",
                borderRadius: 3,
                p: { xs: 3, sm: 4 },
                boxShadow: 3,
              }
            : {}
        }
      >
        {standalone && (
          <Box sx={{ mb: 4 }}>
            <Brand />
          </Box>
        )}
        <Heading
          title={t(
            standalone ? "双重验证" : reauth ? "重新验证身份" : "账户安全",
          )}
          description={t(
            standalone
              ? "完成身份验证后继续登录。"
              : "管理验证器和账户恢复方式。",
          )}
        />
        {d.error && (
          <Alert ref={errorRef} tabIndex={-1} severity="error" sx={{ mb: 2 }}>
            {errorText(d.error)}
          </Alert>
        )}
        {!authenticationPending && !reauth && d.readiness && (
          <Panel title={t("账户恢复检查")}>
            <Stack spacing={2}>
              <Alert
                severity={
                  d.readiness.password || d.readiness.oidc
                    ? "success"
                    : "warning"
                }
              >
                {d.readiness.password || d.readiness.oidc
                  ? t("已配置可用于敏感操作再认证的登录方式。")
                  : t("请设置本地密码或绑定 OIDC 账号，以免无法完成敏感操作。")}
              </Alert>
              <Alert
                severity={d.readiness.password_recovery ? "success" : "warning"}
              >
                {d.readiness.password_recovery
                  ? t("已验证联系方式可用于设置或重置本地密码。")
                  : t("请验证邮箱或手机号；密码恢复还需要管理员配置通知服务。")}
              </Alert>
              {d.enabled && (
                <Alert
                  severity={
                    d.readiness.recovery_codes_remaining > 2
                      ? "info"
                      : "warning"
                  }
                >
                  {t("剩余恢复码：{{0}}。请离线保存，数量不足时重新生成。", {
                    "0": d.readiness.recovery_codes_remaining,
                  })}
                </Alert>
              )}
              <Button component={RouterLink} to="/account/identities">
                {t("管理登录方式")}
              </Button>
            </Stack>
          </Panel>
        )}
        {d.required && !d.enabled && (
          <Alert severity="warning" sx={{ mb: 3 }}>
            {t("管理员必须启用双重验证后才能继续。")}
          </Alert>
        )}
        {d.recovery && (
          <Alert severity="warning" sx={{ mb: 3 }}>
            {t("恢复码已使用，请重新绑定验证器以恢复账户访问。")}
          </Alert>
        )}
        {!!d.codes.length ? (
          <Panel title={t("保存恢复码")}>
            <Alert severity="warning">
              {t("恢复码仅显示一次，请离线保存。每个恢复码只能使用一次。")}
            </Alert>
            <Box
              component="pre"
              sx={{ whiteSpace: "pre-wrap", userSelect: "all" }}
            >
              {d.codes.join("\n")}
            </Box>
            <Button component={RouterLink} to={d.redirect}>
              {t("已保存，继续")}
            </Button>
          </Panel>
        ) : reauth ? (
          <Panel title={t("重新验证身份")}>
            {d.has_password ? (
              <FieldsForm
                disabled={busy}
                onBusyChange={setBusy}
                fields={[
                  {
                    name: "password",
                    label: t("当前密码"),
                    type: "password",
                    autoComplete: "current-password",
                    required: true,
                  },
                  ...(d.enabled
                    ? [
                        {
                          name: "code",
                          label: t("验证器验证码"),
                          required: true,
                        },
                      ]
                    : []),
                ]}
                submit={(v) => submit("reauth", v)}
              />
            ) : !d.providers?.length ? (
              <Stack spacing={2}>
                <Alert severity="warning">
                  {t(
                    "请通过已验证联系方式设置本地密码，再登录完成身份验证。未配置恢复方式时，请联系管理员。",
                  )}
                </Alert>
                <Button component={RouterLink} to="/sso/forgot-password">
                  {t("设置或找回密码")}
                </Button>
              </Stack>
            ) : (
              <Stack spacing={2.5}>
                <Typography>
                  {t("使用已绑定的 OIDC 账号重新验证，然后输入验证器验证码。")}
                </Typography>
                <Stack spacing={1.5}>
                  {d.providers?.map((p) => (
                    <FieldsForm
                      disabled={busy}
                      onBusyChange={setBusy}
                      key={p.key}
                      fields={[]}
                      label={p.name}
                      submit={() =>
                        mutate(`/account/reauth/${encodeURIComponent(p.key)}`, {
                          redirect: d.redirect,
                        })
                      }
                    />
                  ))}
                </Stack>
                <FieldsForm
                  disabled={busy}
                  onBusyChange={setBusy}
                  fields={
                    d.enabled
                      ? [
                          {
                            name: "code",
                            label: t("验证器验证码"),
                            required: true,
                          },
                        ]
                      : []
                  }
                  submit={(v) => submit("reauth", v)}
                />
              </Stack>
            )}
          </Panel>
        ) : d.pending && d.enabled && !d.recovery ? (
          <>
            <Panel title={t("双重验证")}>
              <FieldsForm
                disabled={busy}
                onBusyChange={setBusy}
                fields={[
                  { name: "code", label: t("验证器验证码"), required: true },
                ]}
                label={t("验证并继续")}
                submit={(v) => submit("verify", v)}
              />
            </Panel>
            <Panel title={t("无法使用验证器？")}>
              <FieldsForm
                disabled={busy}
                onBusyChange={setBusy}
                fields={[{ name: "code", label: t("恢复码"), required: true }]}
                submit={(v) => submit("recover", v)}
                label={t("使用恢复码")}
              />
              <Alert severity="info" sx={{ mt: 2 }}>
                {t(
                  "验证器和恢复码均丢失时，请联系管理员核验身份，申请临时恢复码。管理员不会索取密码或验证器密钥。",
                )}
              </Alert>
            </Panel>
          </>
        ) : !d.enabled || d.recovery ? (
          <Panel title={t("设置验证器")}>
            {d.secret ? (
              <Stack spacing={2.5}>
                <Typography>
                  {t("扫描二维码或在验证器中手动输入密钥，再输入验证码确认。")}
                </Typography>
                <Box
                  component="img"
                  src={`data:image/png;base64,${d.qr}`}
                  alt={t("验证器二维码")}
                  sx={{ width: 220, maxWidth: "100%", alignSelf: "center" }}
                />
                <Box
                  component="pre"
                  sx={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}
                >
                  {d.secret}
                </Box>
                <FieldsForm
                  disabled={busy}
                  onBusyChange={setBusy}
                  fields={[
                    { name: "code", label: t("验证器验证码"), required: true },
                  ]}
                  submit={(v) => submit("enable", v)}
                  label={t("启用双重验证")}
                />
              </Stack>
            ) : (
              <FieldsForm
                disabled={busy}
                onBusyChange={setBusy}
                fields={[]}
                submit={() => submit("setup")}
                label={t("开始设置")}
              />
            )}
          </Panel>
        ) : (
          <>
            <Panel title={t("双重验证已启用")}>
              <Stack spacing={3}>
                <Typography>{t("每次新登录都需要验证器验证码。")}</Typography>
                <FieldsForm
                  disabled={busy}
                  onBusyChange={setBusy}
                  fields={[
                    { name: "code", label: t("验证器验证码"), required: true },
                  ]}
                  submit={(v) => submit("codes", v)}
                  label={t("重新生成恢复码")}
                />
                {!d.required && (
                  <FieldsForm
                    disabled={busy}
                    onBusyChange={setBusy}
                    fields={[
                      {
                        name: "code",
                        label: t("验证器验证码"),
                        required: true,
                      },
                    ]}
                    submit={(v) => submit("disable", v)}
                    label={t("关闭双重验证")}
                  />
                )}
              </Stack>
            </Panel>
          </>
        )}
        <Stack
          direction="row"
          sx={{ flexWrap: "wrap", alignItems: "center", gap: 1 }}
        >
          {(d.pending || d.recovery) && (
            <FieldsForm
              disabled={busy}
              onBusyChange={setBusy}
              fields={[]}
              submitSize="medium"
              label={t("退出登录")}
              submit={() => mutate("/account/logout")}
            />
          )}
          {!standalone && (
            <>
              <Button component={RouterLink} to="/account/login">
                {t("重新登录")}
              </Button>
              <Button
                component={RouterLink}
                to="/account/change-password"
                disabled={authenticationPending}
              >
                {t("管理密码")}
              </Button>
              <Button
                component={RouterLink}
                to="/account/reauth?redirect=%2Faccount%2Fsecurity"
              >
                {t("重新验证身份")}
              </Button>
              <Button
                component={RouterLink}
                to="/account/profile"
                disabled={authenticationPending}
              >
                {t("返回个人中心")}
              </Button>
            </>
          )}
        </Stack>
      </Box>
    </Box>
  );
}
export function AdminRoles({
  data,
  mutate,
  ask,
}: { data: ViewDataMap["AdminRolesView"] } & Pick<Actions, "mutate" | "ask">) {
  useLocale();
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState(params.get("q") || "");
  const [search, setSearch] = useState("");
  const [options, setOptions] = useState<{ id: string; username: string }[]>(
    [],
  );
  const [selected, setSelected] = useState<{
    id: string;
    username: string;
  } | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    setOptions([]);
    setSearchError("");
    if (!search.trim() || selected?.username === search) {
      setSearching(false);
      return;
    }
    setSearching(true);
    const timer = setTimeout(async () => {
      try {
        const response = await fetch(
          `/dashboard/admins/users?q=${encodeURIComponent(search.trim())}`,
          {
            headers: { Accept: "application/json" },
            signal: controller.signal,
          },
        );
        if (!response.ok) throw new Error(errorText(String(response.status)));
        const result = await response.json();
        if (!Array.isArray(result.users)) throw new Error(errorText("401"));
        setOptions(result.users);
      } catch (e) {
        if (!controller.signal.aborted) setSearchError((e as Error).message);
      } finally {
        if (!controller.signal.aborted) setSearching(false);
      }
    }, 300);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [search, selected]);
  function filter(name: string, value: string) {
    const next = new URLSearchParams(params);
    value ? next.set(name, value) : next.delete(name);
    next.delete("page");
    setParams(next);
  }
  return (
    <>
      <Heading
        title={t("管理员")}
        description={t(
          "超级管理员拥有所有权限；普通管理员按全局能力和具体应用分配权限。",
        )}
      />
      <Panel title={t("管理员列表")}>
        <Stack direction={{ xs: "column", sm: "row" }} sx={{ gap: 2, mb: 3 }}>
          <Box
            component="form"
            onSubmit={(e) => {
              e.preventDefault();
              filter("q", query);
            }}
            sx={{ width: { xs: "100%", sm: 320 } }}
          >
            <TextField
              fullWidth
              size="small"
              label={t("搜索用户名")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </Box>
          <TextField
            select
            size="small"
            label={t("角色")}
            value={params.get("role") || ""}
            onChange={(e) => filter("role", e.target.value)}
            sx={{ minWidth: 180 }}
          >
            <MenuItem value="">{t("全部")}</MenuItem>
            <MenuItem value="super_admin">{t("超级管理员")}</MenuItem>
            <MenuItem value="admin">{t("普通管理员")}</MenuItem>
          </TextField>
        </Stack>
        {data.rows.map((r) => (
          <Box
            key={r.user_id}
            sx={{ py: 2, borderTop: "1px solid", borderColor: "divider" }}
          >
            <Stack
              direction="row"
              sx={{ gap: 1.5, alignItems: "center", flexWrap: "wrap" }}
            >
              <Typography sx={{ fontWeight: 600 }}>{r.username}</Typography>
              <Chip
                size="small"
                color={r.role === "super_admin" ? "primary" : "default"}
                label={t(
                  r.role === "super_admin" ? "超级管理员" : "普通管理员",
                )}
              />
              <Button
                color="error"
                disabled={r.user_id === data.current_user_id}
                sx={{ ml: "auto" }}
                onClick={() =>
                  ask(
                    t("移除管理员"),
                    "/dashboard/admins",
                    { username: r.username, role: "remove" },
                    t("确认移除 {{0}} 的管理员权限？", { "0": r.username }),
                  )
                }
              >
                {t("移除管理员")}
              </Button>
            </Stack>
            {r.role === "admin" && (
              <AdminPermissions
                key={`${r.user_id}-${r.grants?.revision}`}
                row={r}
                data={data}
                mutate={mutate}
              />
            )}
          </Box>
        ))}
        {!data.rows.length && <Empty />}
        {data.total_pages > 1 && (
          <Pagination
            sx={{ mt: 2 }}
            count={data.total_pages}
            page={data.page}
            onChange={(_, page) => {
              const next = new URLSearchParams(params);
              next.set("page", String(page));
              setParams(next);
            }}
          />
        )}
      </Panel>
      <Panel title={t("设置管理员角色")}>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {t("不能修改自己的管理员角色，请由其他超级管理员操作。")}
        </Typography>
        <Autocomplete
          options={options}
          value={selected}
          inputValue={search}
          loading={searching}
          disabled={busy}
          filterOptions={(values) => values}
          getOptionLabel={(user) => user.username}
          getOptionDisabled={(user) => user.id === data.current_user_id}
          isOptionEqualToValue={(a, b) => a.id === b.id}
          onInputChange={(_, value, reason) => {
            setSearch(value);
            if (reason === "input") setSelected(null);
          }}
          onChange={(_, value) => setSelected(value)}
          noOptionsText={t(search.trim() ? "无匹配用户" : "输入用户名搜索")}
          loadingText={t("正在搜索…")}
          renderInput={(props) => (
            <TextField
              {...props}
              label={t("搜索并选择用户")}
              error={!!searchError}
              helperText={
                searchError || t("输入用户名搜索，仅可选择匹配的用户。")
              }
            />
          )}
          sx={{ maxWidth: 480, mb: 3 }}
        />
        <Box sx={{ maxWidth: 480 }}>
          <FieldsForm
            fields={[
              {
                name: "role",
                label: t("角色"),
                required: true,
                default: "admin",
                options: [
                  ["super_admin", t("超级管理员")],
                  ["admin", t("普通管理员")],
                ],
              },
            ]}
            disabled={!selected || selected.id === data.current_user_id}
            onBusyChange={setBusy}
            submit={(v) =>
              mutate("/dashboard/admins", {
                ...v,
                username: selected!.username,
              })
            }
          />
        </Box>
      </Panel>
    </>
  );
}
