import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  TextField,
  Typography,
} from "@mui/material";
import { useState } from "react";
import { FieldsForm, type Field } from "./forms";
import type { Values } from "./contracts";
import type { Actions } from "./shared";
import { t, useLocale } from "./i18n";

interface DialogHeading {
  title: string;
  description?: string;
}
export type ActionModal = DialogHeading &
  (
    | { kind: "confirm"; endpoint: string; values?: Values }
    | {
        kind: "editor";
        endpoint: string;
        fields: Field[];
        initial?: Values;
        values?: Values;
      }
    | { kind: "secret"; secret: string }
  );
export function ActionDialog({
  modal,
  mutate,
  onClose,
}: {
  modal: ActionModal;
  mutate: Actions["mutate"];
  onClose: () => void;
}) {
  useLocale();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <Dialog
      open
      onClose={() => {
        if (!busy) onClose();
      }}
      maxWidth={modal.kind === "editor" ? "md" : "sm"}
      fullWidth
    >
      <DialogTitle>{t(modal.title)}</DialogTitle>
      <DialogContent>
        {modal.description && (
          <Typography color="text.secondary" sx={{ mb: 3 }}>
            {t(modal.description)}
          </Typography>
        )}
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {t(error)}
          </Alert>
        )}
        {modal.kind === "secret" ? (
          <TextField
            label={t("客户端密钥")}
            value={modal.secret}
            fullWidth
            multiline
            slotProps={{ input: { readOnly: true } }}
          />
        ) : modal.kind === "editor" ? (
          <Box sx={{ pt: 1 }}>
            <FieldsForm
              fields={modal.fields}
              initial={modal.initial}
              onBusyChange={setBusy}
              onCancel={onClose}
              submit={(values) =>
                mutate(modal.endpoint, { ...modal.values, ...values })
              }
            />
          </Box>
        ) : null}
      </DialogContent>
      {modal.kind !== "editor" && (
        <DialogActions>
          <Button disabled={busy} onClick={onClose}>
            {modal.kind === "secret" ? t("已保存，关闭") : t("取消")}
          </Button>
          {modal.kind === "confirm" && (
            <Button
              variant="contained"
              color="inherit"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setError("");
                try {
                  await mutate(modal.endpoint, modal.values);
                } catch (e) {
                  setError((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? t("正在处理…") : t("确认")}
            </Button>
          )}
        </DialogActions>
      )}
    </Dialog>
  );
}
