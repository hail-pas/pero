import {
  ArrowBackRounded,
  CheckRounded,
  ContentCopyRounded,
  SearchRounded,
} from "@mui/icons-material";
import {
  Box,
  Button,
  Card,
  CardContent,
  IconButton,
  Pagination,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import { useState } from "react";
import { Link as RouterLink } from "react-router-dom";
import { lower, type Values } from "./api";
import { Label } from "./components/label";
import { type Field } from "./forms";
import { t, useLocale } from "./i18n";

export const names: Record<string, string> = {
  apps: "应用",
  users: "用户",
  providers: "身份提供方",
};

/** Page title block shared by every workspace screen. */
export function Heading({
  title,
  description,
  back,
  action,
}: {
  title: string;
  description?: React.ReactNode;
  back?: string;
  action?: React.ReactNode;
}) {
  useLocale();
  return (
    <Box sx={{ mb: { xs: 3, md: 4 } }}>
      {back && (
        <Button
          component={RouterLink}
          to={back}
          startIcon={<ArrowBackRounded />}
          size="small"
          color="inherit"
          sx={{ mb: 1.5, ml: -0.5 }}
        >
          {t("返回列表")}
        </Button>
      )}
      <Stack
        direction={{ xs: "column", sm: "row" }}
        sx={{
          alignItems: { xs: "flex-start", sm: "flex-end" },
          justifyContent: "space-between",
          gap: 2,
        }}
      >
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="h4">{title}</Typography>
          {description ? (
            <Typography
              variant="body2"
              color="text.secondary"
              sx={{ mt: 1, maxWidth: 760 }}
            >
              {description}
            </Typography>
          ) : null}
        </Box>
        {action ? (
          <Box
            sx={{
              flexShrink: 0,
              display: "flex",
              flexWrap: "wrap",
              gap: 1,
              alignItems: "center",
            }}
          >
            {action}
          </Box>
        ) : null}
      </Stack>
    </Box>
  );
}

/** A card with a compact header, used for every section on a page. */
export function Panel({
  title,
  description,
  children,
  action,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  children: React.ReactNode;
  action?: React.ReactNode;
}) {
  useLocale();
  return (
    <Card sx={{ mb: 3 }}>
      <Stack
        direction="row"
        sx={{
          justifyContent: "space-between",
          alignItems: "flex-start",
          flexWrap: "wrap",
          gap: 2,
          px: 3,
          pt: 2.75,
          pb: 1.5,
        }}
      >
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="h6" sx={{ overflowWrap: "anywhere" }}>
            {title}
          </Typography>
          {description ? (
            <Typography
              variant="body2"
              color="text.secondary"
              sx={{ mt: 0.5, maxWidth: 720 }}
            >
              {description}
            </Typography>
          ) : null}
        </Box>
        {action ? (
          <Box
            sx={{
              display: "flex",
              flexWrap: "wrap",
              alignItems: "center",
              gap: 1,
            }}
          >
            {action}
          </Box>
        ) : null}
      </Stack>
      <CardContent sx={{ px: 3, pt: 1, pb: 3 }}>{children}</CardContent>
    </Card>
  );
}

const statusMap: Record<
  string,
  { label: string; color: "success" | "warning" | "info" | "error" | "default" }
> = {
  active: { label: "已启用", color: "success" },
  enabled: { label: "已启用", color: "success" },
  true: { label: "已启用", color: "success" },
  locked: { label: "已锁定", color: "warning" },
  pending: { label: "待处理", color: "warning" },
  pending_approval: { label: "待审批", color: "warning" },
  pending_verification: { label: "待验证", color: "warning" },
  ready: { label: "待完成", color: "info" },
  completed: { label: "已完成", color: "success" },
  disabled: { label: "已停用", color: "default" },
  false: { label: "已停用", color: "default" },
  expired: { label: "已过期", color: "default" },
  deleted: { label: "已删除", color: "error" },
  revoked: { label: "已撤销", color: "error" },
};

export function Status({ value }: { value: unknown }) {
  useLocale();
  const status = statusMap[lower(value)];
  if (status)
    return <Label color={status.color}>{t(status.label)}</Label>;
  return <Label>{t("已停用")}</Label>;
}

export function Empty({ text = t("暂无数据") }: { text?: string }) {
  useLocale();
  return (
    <Stack sx={{ alignItems: "center", py: 6, textAlign: "center" }}>
      <Box
        sx={{
          display: "grid",
          placeItems: "center",
          width: 52,
          height: 52,
          borderRadius: "50%",
          bgcolor: "background.neutral",
          color: "text.disabled",
          mb: 2,
        }}
      >
        <SearchRounded sx={{ fontSize: 24 }} />
      </Box>
      <Typography variant="subtitle2">{t(text)}</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.75 }}>
        {t("调整筛选条件或创建新的记录。")}
      </Typography>
    </Stack>
  );
}

/** Search and filter controls aligned above a table or list. */
export function Toolbar({
  children,
  actions,
}: {
  children: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <Stack
      direction={{ xs: "column", md: "row" }}
      spacing={2}
      sx={{
        justifyContent: "space-between",
        alignItems: { xs: "stretch", md: "center" },
        gap: 2,
        p: 3,
      }}
    >
      <Stack
        direction={{ xs: "column", sm: "row" }}
        spacing={2}
        sx={{ flex: 1, alignItems: { xs: "stretch", sm: "center" }, gap: 2 }}
      >
        {children}
      </Stack>
      {actions}
    </Stack>
  );
}

/** Label/value grid for detail panels. */
export function MetaGrid({
  items,
  columns = 2,
}: {
  items: [React.ReactNode, React.ReactNode][];
  columns?: 2 | 3;
}) {
  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: {
          xs: "minmax(0, 1fr)",
          sm: columns === 3 ? "repeat(2, minmax(0, 1fr))" : "minmax(0,1fr)",
          md: `repeat(${columns}, minmax(0, 1fr))`,
        },
        gap: 2.5,
        rowGap: 2.5,
      }}
    >
      {items.map(([label, value], index) => (
        <Box key={index} sx={{ minWidth: 0 }}>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ display: "block" }}
          >
            {label}
          </Typography>
          <Typography variant="body2" sx={{ mt: 0.5, fontWeight: 500 }}>
            {value || "—"}
          </Typography>
        </Box>
      ))}
    </Box>
  );
}

/** Pagination row with a record summary, used under lists and tables. */
export function PaginationFooter({
  page,
  totalPages,
  count,
  onChange,
}: {
  page: number;
  totalPages: number;
  count?: number;
  onChange: (page: number) => void;
}) {
  useLocale();
  return (
    <Stack
      direction={{ xs: "column", sm: "row" }}
      sx={{
        justifyContent: "space-between",
        alignItems: { xs: "flex-start", sm: "center" },
        gap: 2,
        px: 3,
        py: 2,
        borderTop: 1,
        borderColor: "divider",
      }}
    >
      <Typography variant="caption" color="text.secondary">
        {count === undefined
          ? t("第 {{0}} 页", { "0": page })
          : t("本页 {{0}} 条记录 · 第 {{1}} 页", {
              "0": count,
              "1": page,
            })}
      </Typography>
      <Pagination
        size="small"
        count={Math.max(1, totalPages)}
        page={page}
        onChange={(_, value) => onChange(value)}
      />
    </Stack>
  );
}

/** Monospace value with an inline copy affordance (secrets, URLs, codes). */
export function Copyable({
  value,
  label,
  block = false,
}: {
  value: string;
  label?: string;
  block?: boolean;
}) {
  useLocale();
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }
  return (
    <Box
      sx={{
        display: "flex",
        alignItems: block ? "flex-start" : "center",
        gap: 1,
        p: block ? 2 : 0,
        borderRadius: 1.5,
        border: block ? 1 : 0,
        borderColor: "divider",
        bgcolor: block ? "background.neutral" : "transparent",
      }}
    >
      <Box
        component="code"
        sx={{
          flex: 1,
          minWidth: 0,
          fontFamily: "monospace",
          fontSize: 13,
          lineHeight: 1.7,
          whiteSpace: "pre-wrap",
          overflowWrap: "anywhere",
          userSelect: "all",
        }}
      >
        {value}
      </Box>
      <Tooltip title={copied ? t("已复制") : t("复制")}>
        <IconButton
          size="small"
          aria-label={label ?? t("复制")}
          onClick={copy}
          sx={{ flexShrink: 0 }}
        >
          {copied ? (
            <CheckRounded fontSize="small" color="success" />
          ) : (
            <ContentCopyRounded fontSize="small" />
          )}
        </IconButton>
      </Tooltip>
    </Box>
  );
}

export type Actions = {
  mutate: (
    endpoint: string,
    values?: Values,
    after?: () => void,
  ) => Promise<void>;
  ask: (
    title: string,
    endpoint: string,
    values?: Values,
    description?: string,
  ) => void;
  editor: (
    title: string,
    endpoint: string,
    fields: Field[],
    initial?: Values,
    values?: Values,
  ) => void;
};
