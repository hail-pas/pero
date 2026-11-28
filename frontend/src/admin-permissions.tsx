import { labelValue, t, useLocale } from "./i18n";
import { useRef, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Divider,
  FormControlLabel,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import type { ViewDataMap } from "./contracts";
import type { Actions } from "./shared";
import { Panel } from "./shared";
import { requestErrorText } from "./api";
type Data = ViewDataMap["AdminRolesView"];
export function AdminPermissions({
  row,
  data,
  mutate,
}: {
  row: Data["rows"][number];
  data: Data;
  mutate: Actions["mutate"];
}) {
  useLocale();
  const [open, setOpen] = useState(false);
  // Keep the revision and preview bound to the grants being edited, even if
  // a focus refresh receives newer permissions from another administrator.
  const [baseline, setBaseline] = useState(row.grants);
  const [global, setGlobal] = useState(row.grants?.global_permissions || []);
  const [apps, setApps] = useState<Record<string, string[]>>(
    row.grants?.app_grants || {},
  );
  const [selected, setSelected] = useState("");
  const [review, setReview] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<{ cause: unknown }>();
  const [targets, setTargets] = useState<string[]>([]);
  const submitting = useRef(false);
  async function save() {
    if (submitting.current) return;
    submitting.current = true;
    setError(undefined);
    setSaving(true);
    try {
      await mutate(`/dashboard/admins/${row.user_id}/permissions`, {
        revision: baseline!.revision,
        global_permissions: JSON.stringify(global),
        app_grants: JSON.stringify(
          Object.entries(apps).map(([app_id, permissions]) => ({
            app_id,
            permissions,
          })),
        ),
      });
      setOpen(false);
    } catch (cause) {
      setError({ cause });
    } finally {
      submitting.current = false;
      setSaving(false);
    }
  }

  function toggle(values: string[], code: string, on: boolean): string[] {
    const next = new Set(values);
    function add(c: string) {
      if (next.has(c)) return;
      next.add(c);
      data.catalog.find((p) => p.code === c)?.dependencies.forEach(add);
    }
    if (on) add(code);
    else {
      next.delete(code);
      let changed = true;
      while (changed) {
        changed = false;
        for (const p of data.catalog)
          if (next.has(p.code) && p.dependencies.some((d) => !next.has(d))) {
            next.delete(p.code);
            changed = true;
          }
      }
    }
    return [...next].sort();
  }
  const checks = (
    scope: string,
    values: string[],
    set: (v: string[]) => void,
  ) =>
    data.catalog
      .filter((p) => p.scope === scope)
      .map((p) => (
        <Stack key={p.code}>
          <FormControlLabel
            control={
              <Checkbox
                disabled={saving}
                checked={values.includes(p.code)}
                onChange={(_, on) => {
                  set(toggle(values, p.code, on));
                  setReview(false);
                }}
              />
            }
            label={`${t(p.name)} (${p.code})`}
          />
          {p.risk && <Alert severity="warning">{t(p.risk)}</Alert>}
        </Stack>
      ));
  const before: Record<string, string[]> = {
    global: baseline?.global_permissions || [],
    ...baseline?.app_grants,
  };
  const after: Record<string, string[]> = { global, ...apps };
  const labels: Record<string, string> = {
    global: t("全局权限"),
    ...Object.fromEntries(data.apps.map(([id, , name]) => [id, name])),
  };
  const targetApps = selected ? data.apps.filter(([id]) => id !== selected) : [];
  const diff = Object.keys({ ...before, ...after })
    .map((id) => ({
      id,
      added: (after[id] || []).filter((p) => !before[id]?.includes(p)),
      removed: (before[id] || []).filter((p) => !after[id]?.includes(p)),
    }))
    .filter((d) => d.added.length || d.removed.length);
  return (
    <>
      <Button
        disabled={saving}
        aria-expanded={open}
        onClick={() => {
          if (!open) {
            setBaseline(row.grants);
            setGlobal(row.grants?.global_permissions || []);
            setApps(row.grants?.app_grants || {});
            setSelected("");
            setTargets([]);
            setReview(false);
            setError(undefined);
          }
          setOpen(!open);
        }}
      >
        {t("分配权限")} · {row.username}
      </Button>
      {open && (
        <Panel title={labelValue("分配权限", row.username)}>
          <Stack spacing={3}>
            <Alert severity="info">
              {t(
                "全局用户权限影响所有非管理员账户。应用权限只对明确选择的应用生效；新应用不会自动获得授权。保存变更后，该管理员需要重新登录。",
              )}
            </Alert>
            {error && (
              <Alert severity="error">{requestErrorText(error.cause)}</Alert>
            )}
            <Box>
              <Typography variant="h6" sx={{ mb: 1 }}>
                {t("全局权限")}
              </Typography>
              {checks("global", global, setGlobal)}
            </Box>
            <Stack spacing={2}>
              <Typography variant="h6">
                {t("应用权限：{{0}} 个应用 / {{1}} 项权限", {
                  "0": Object.keys(apps).length,
                  "1": Object.values(apps).reduce(
                    (count, permissions) => count + permissions.length,
                    0,
                  ),
                })}
              </Typography>
              <TextField
                disabled={saving}
                fullWidth
                select
                label={t("选择应用")}
                value={selected}
                sx={{ maxWidth: 480 }}
                onChange={(e) => {
                  setSelected(e.target.value);
                  setTargets([]);
                }}
              >
                <MenuItem value="">{t("请选择")}</MenuItem>
                {data.apps.map(([id, , name]) => (
                  <MenuItem key={id} value={id}>
                    {name}
                  </MenuItem>
                ))}
              </TextField>
              {selected && (
                <Box>
                  {checks("app", apps[selected] || [], (v) =>
                    setApps((prev) => {
                      const next = { ...prev };
                      if (v.length) next[selected] = v;
                      else delete next[selected];
                      return next;
                    }),
                  )}
                  <Button
                    disabled={saving || !apps[selected]?.length}
                    sx={{ mt: 1 }}
                    onClick={() => {
                      setApps((prev) => {
                        const next = { ...prev };
                        delete next[selected];
                        return next;
                      });
                      setReview(false);
                    }}
                  >
                    {t("撤回该应用全部权限")}
                  </Button>
                </Box>
              )}
              {targetApps.length > 0 && (
                <Stack spacing={1.5}>
                  <TextField
                    disabled={saving}
                    fullWidth
                    select
                    label={t("目标应用")}
                    value={targets}
                    sx={{ maxWidth: 480 }}
                    slotProps={{
                      select: {
                        multiple: true,
                        renderValue: () =>
                          targets.length === 1
                            ? (labels[targets[0]] ?? targets[0])
                            : t("已选 {{0}} 个应用", { "0": targets.length }),
                      },
                    }}
                    onChange={(e) =>
                      setTargets(
                        typeof e.target.value === "string"
                          ? e.target.value.split(",")
                          : e.target.value,
                      )
                    }
                  >
                    {targetApps.map(([id, , name]) => (
                      <MenuItem key={id} value={id}>
                        {name}
                      </MenuItem>
                    ))}
                  </TextField>
                  <Stack direction="row" sx={{ flexWrap: "wrap", gap: 1 }}>
                    <Button
                      disabled={saving}
                      onClick={() => setTargets(targetApps.map(([id]) => id))}
                    >
                      {t("全选其他应用")}
                    </Button>
                    <Button
                      disabled={
                        saving || !targets.length || !apps[selected]?.length
                      }
                      onClick={() => {
                        setApps((prev) => ({
                          ...prev,
                          ...Object.fromEntries(
                            targets.map((id) => [id, [...prev[selected]]]),
                          ),
                        }));
                        setReview(false);
                      }}
                    >
                      {t("复制勾选到已选应用")}
                    </Button>
                  </Stack>
                </Stack>
              )}
            </Stack>
            <Divider />
            <Stack direction="row" sx={{ flexWrap: "wrap", gap: 1 }}>
              <Button
                disabled={saving}
                color="warning"
                onClick={() => {
                  setGlobal([]);
                  setApps({});
                  setReview(false);
                }}
              >
                {t("清空全部权限")}
              </Button>
              <Button
                variant="outlined"
                disabled={saving || !diff.length}
                onClick={() => setReview(true)}
              >
                {t("预览权限变更")}
              </Button>
            </Stack>
            {review && (
              <Stack spacing={1.5} sx={{ alignItems: "flex-start" }}>
                <Typography>{t("确认以下新增和撤回：")}</Typography>
                {diff.map((d) => (
                  <Alert key={d.id} severity="warning" sx={{ width: "100%" }}>
                    {labels[d.id] || d.id} · {t("新增")}{" "}
                    {d.added.join(", ") || "—"} · {t("撤回")}{" "}
                    {d.removed.join(", ") || "—"}
                  </Alert>
                ))}
                <Button variant="contained" disabled={saving} onClick={save}>
                  {t("确认保存")}
                </Button>
              </Stack>
            )}
          </Stack>
        </Panel>
      )}
    </>
  );
}
