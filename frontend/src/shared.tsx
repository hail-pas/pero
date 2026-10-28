import { ArrowBackRounded, SearchRounded } from "@mui/icons-material";
import {
  Box,
  Button,
  Card,
  CardContent,
  Stack,
  Typography,
} from "@mui/material";
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
export function Heading({
  title,
  description,
  back,
  action,
}: {
  title: string;
  description?: string;
  back?: string;
  action?: React.ReactNode;
}) {
  useLocale();
  return (
    <Box sx={{ mb: 4.5 }}>
      {back && (
        <Button
          component={RouterLink}
          to={back}
          startIcon={<ArrowBackRounded />}
          size="small"
          color="inherit"
          sx={{ mb: 2 }}
        >
          {t("返回列表")}
        </Button>
      )}
      <Stack
        direction={{ xs: "column", sm: "row" }}
        sx={{
          alignItems: { xs: "flex-start", sm: "center" },
          justifyContent: "space-between",
          gap: 2,
        }}
      >
        <Box sx={{ minWidth: 0, overflowWrap: "anywhere" }}>
          <Typography variant="h4" sx={{ mb: 0.75, letterSpacing: "-.025em" }}>
            {title}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {description}
          </Typography>
        </Box>
        {action}
      </Stack>
    </Box>
  );
}
export function Panel({
  title,
  children,
  action,
}: {
  title: string;
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
          alignItems: "center",
          flexWrap: "wrap",
          gap: 2,
          px: 3,
          pt: 3,
          pb: 2,
        }}
      >
        <Typography variant="h6" sx={{ minWidth: 0, overflowWrap: "anywhere" }}>
          {title}
        </Typography>
        {action}
      </Stack>
      <CardContent sx={{ px: 3, pt: 1, pb: 3 }}>{children}</CardContent>
    </Card>
  );
}
export function Status({ value }: { value: unknown }) {
  useLocale();
  const good = ["active", "true"].includes(lower(value));
  return (
    <Label
      color={
        good ? "success" : lower(value) === "locked" ? "warning" : "default"
      }
    >
      {good
        ? t("已启用")
        : lower(value) === "locked"
          ? t("已锁定")
          : t("已停用")}
    </Label>
  );
}
export function Empty({ text = t("暂无数据") }: { text?: string }) {
  useLocale();
  return (
    <Stack sx={{ alignItems: "center", py: 7 }}>
      <SearchRounded sx={{ fontSize: 42, color: "text.disabled", mb: 1 }} />
      <Typography variant="subtitle2">{t(text)}</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
        {t("调整筛选条件或创建新的记录。")}
      </Typography>
    </Stack>
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
