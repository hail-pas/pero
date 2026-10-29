import { t, useLocale } from "./i18n";
import { useRef, useState } from "react";
import {
  Alert,
  Button,
  Checkbox,
  FormControlLabel,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import type { ViewDataMap } from "./contracts";
import type { Actions } from "./shared";
import { Panel } from "./shared";
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
  const [global, setGlobal] = useState(row.grants?.global_permissions || []);
  const [apps, setApps] = useState<Record<string, string[]>>(
    row.grants?.app_grants || {},
  );
  const [selected, setSelected] = useState("");
  const [review, setReview] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [targets, setTargets] = useState<string[]>([]);
  const submitting = useRef(false);
  async function save() {
    if (submitting.current) return;
    submitting.current = true;
    setError("");
    setSaving(true);
    try {
      await mutate(`/dashboard/admins/${row.user_id}/permissions`, {
        revision: row.grants!.revision,
        global_permissions: JSON.stringify(global),
        app_grants: JSON.stringify(
          Object.entries(apps).map(([app_id, permissions]) => ({
            app_id,
            permissions,
          })),
        ),
      });
      setOpen(false);
    } catch (e) {
      setError((e as Error).message);
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
    global: row.grants?.global_permissions || [],
    ...row.grants?.app_grants,
  };
  const after: Record<string, string[]> = { global, ...apps };
  const labels: Record<string, string> = {
    global: t("全局权限"),
    ...Object.fromEntries(data.apps.map(([id, , name]) => [id, name])),
  };
  const diff = Object.keys({ ...before, ...after })
    .map((id) => ({
      id,
      added: (after[id] || []).filter((p) => !before[id]?.includes(p)),
      removed: (before[id] || []).filter((p) => !after[id]?.includes(p)),
    }))
    .filter((d) => d.added.length || d.removed.length);
  return (
    <>
      <Button disabled={saving} onClick={() => setOpen(!open)}>
        {t("分配权限")} · {row.username}
      </Button>
      {open && (
        <Panel title={`${t("分配权限")}：${row.username}`}>
          <Alert severity="info">
            {t(
              "全局用户权限影响所有非管理员账户。应用权限只对明确选择的应用生效；新应用不会自动获得授权。保存变更后，该管理员需要重新登录。",
            )}
          </Alert>
          {error && <Alert severity="error">{t(error)}</Alert>}
          <Typography variant="h6">{t("全局权限")}</Typography>
          {checks("global", global, setGlobal)}
          <Typography variant="h6">
            {t("应用权限：{{0}} 个应用 / {{1}} 项权限", {
              "0": Object.keys(apps).length,
              "1": Object.values(apps).flat().length,
            })}
          </Typography>
          <TextField
            disabled={saving}
            select
            label={t("选择应用")}
            value={selected}
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
            <>
              <Typography>{labels[selected]}</Typography>
              {checks("app", apps[selected] || [], (v) =>
                setApps((prev) => {
                  const next = { ...prev };
                  if (v.length) next[selected] = v;
                  else delete next[selected];
                  return next;
                }),
              )}
              <Button
                disabled={saving}
                onClick={() => {
                  setApps((prev) => {
                    const n = { ...prev };
                    delete n[selected];
                    return n;
                  });
                  setReview(false);
                }}
              >
                {t("撤回该应用全部权限")}
              </Button>
            </>
          )}
          {selected && (
            <>
              <TextField
                disabled={saving}
                select
                label={t("复制当前勾选到指定应用")}
                value={targets}
                slotProps={{ select: { multiple: true } }}
                onChange={(e) =>
                  setTargets(
                    typeof e.target.value === "string"
                      ? e.target.value.split(",")
                      : e.target.value,
                  )
                }
              >
                {data.apps
                  .filter(([id]) => id !== selected)
                  .map(([id, , name]) => (
                    <MenuItem key={id} value={id}>
                      {name}
                    </MenuItem>
                  ))}
              </TextField>
              <Button
                disabled={saving}
                onClick={() =>
                  setTargets(
                    data.apps
                      .filter(([id]) => id !== selected)
                      .map(([id]) => id),
                  )
                }
              >
                {t("全选当前应用")}
              </Button>
              <Button
                disabled={saving || !targets.length || !apps[selected]?.length}
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
            </>
          )}
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
            disabled={saving || !diff.length}
            onClick={() => setReview(true)}
          >
            {t("预览权限变更")}
          </Button>
          {review && (
            <>
              <Typography>{t("确认以下新增和撤回：")}</Typography>
              {diff.map((d) => (
                <Alert key={d.id} severity="warning">
                  {labels[d.id] || d.id} · {t("新增")}{" "}
                  {d.added.join(", ") || "—"} · {t("撤回")}{" "}
                  {d.removed.join(", ") || "—"}
                </Alert>
              ))}
              <Button variant="contained" disabled={saving} onClick={save}>
                {t("确认保存")}
              </Button>
            </>
          )}
        </Panel>
      )}
    </>
  );
}
