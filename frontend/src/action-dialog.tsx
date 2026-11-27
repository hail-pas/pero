import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  InputAdornment,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { ContentCopyRounded } from "@mui/icons-material";
import { useState } from "react";
import { FieldsForm, type Field } from "./forms";
import type { Values } from "./contracts";
import type { Actions } from "./shared";
import { t, useLocale, type Message } from "./i18n";
import { useAction } from "./use-action";

interface DialogHeading {
  title: Message;
  description?: Message;
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
    | { kind: "secret"; secret: string; label?: string }
  );

/** Destructive endpoints get the error tone without changing every call site. */
function isDestructive(modal: ActionModal) {
  if (modal.kind !== "confirm") return false;
  return /revoke|delete|remove|disable|unlink|retire|reset|close|reject|withdraw|leave|suspend|lock|撤销|删除|停用|移除|解绑|解散|注销|重置|拒绝|撤回|退出|锁定/i.test(
    `${t(modal.title)} ${modal.endpoint}`,
  );
}

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
  const [formBusy, setFormBusy] = useState(false);
  const { busy: actionBusy, error, run } = useAction();
  const busy = formBusy || actionBusy;
  const [copied, setCopied] = useState(false);
  const destructive = isDestructive(modal);
  async function copySecret() {
    if (modal.kind !== "secret") return;
    try {
      await navigator.clipboard.writeText(modal.secret);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }
  return (
    <Dialog
      open
      onClose={() => {
        // One-time credentials require the explicit saved/close action.
        if (!busy && modal.kind !== "secret") onClose();
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
            {error}
          </Alert>
        )}
        {modal.kind === "secret" ? (
          <TextField
            label={t(modal.label || "客户端密钥")}
            value={modal.secret}
            fullWidth
            multiline
            slotProps={{
              input: {
                readOnly: true,
                sx: { fontFamily: "monospace", fontSize: 13 },
                endAdornment: (
                  <InputAdornment position="end" sx={{ alignSelf: "flex-start", mt: 1 }}>
                    <Tooltip title={copied ? t("已复制") : t("复制")}>
                      <IconButton
                        aria-label={t("复制")}
                        size="small"
                        onClick={copySecret}
                      >
                        {copied ? (
                          <span aria-hidden>✓</span>
                        ) : (
                          <ContentCopyRounded fontSize="small" />
                        )}
                      </IconButton>
                    </Tooltip>
                  </InputAdornment>
                ),
              },
            }}
          />
        ) : modal.kind === "editor" ? (
          <Box sx={{ pt: 1 }}>
            <FieldsForm
              fields={modal.fields}
              initial={modal.initial}
              onBusyChange={setFormBusy}
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
          <Button disabled={busy} onClick={onClose} color="inherit">
            {modal.kind === "secret" ? t("已保存，关闭") : t("取消")}
          </Button>
          {modal.kind === "confirm" && (
            <Button
              variant="contained"
              color={destructive ? "error" : "primary"}
              disabled={busy}
              onClick={() => run(() => mutate(modal.endpoint, modal.values))}
            >
              {busy ? t("正在处理…") : t("确认")}
            </Button>
          )}
        </DialogActions>
      )}
    </Dialog>
  );
}
