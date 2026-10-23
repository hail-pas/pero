import { CheckRounded, TranslateRounded } from "@mui/icons-material";
import { Button, ListItemText, Menu, MenuItem } from "@mui/material";
import { useState } from "react";
import { t, useLocale } from "./i18n";
export function LanguageSwitcher() {
  const { locale, setLocale } = useLocale();
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  return (
    <>
      <Button
        aria-label={t("切换语言")}
        aria-haspopup="menu"
        aria-expanded={!!anchor}
        onClick={(e) => setAnchor(e.currentTarget)}
        color="inherit"
        startIcon={<TranslateRounded sx={{ fontSize: 18 }} />}
        sx={{ minWidth: 0, px: 1.5, color: "text.secondary", fontWeight: 600 }}
      >
        {locale === "en" ? "EN" : "中文"}
      </Button>
      <Menu
        anchorEl={anchor}
        open={!!anchor}
        onClose={() => setAnchor(null)}
        slotProps={{ paper: { sx: { minWidth: 200, p: 0.5 } } }}
      >
        {(
          [
            ["zh-CN", "简体中文", "Chinese"],
            ["en", "English", "英语"],
          ] as const
        ).map(([value, label, subtitle]) => (
          <MenuItem
            key={value}
            selected={locale === value}
            onClick={() => {
              setLocale(value);
              setAnchor(null);
            }}
            sx={{ gap: 2, py: 1, borderRadius: 1 }}
          >
            <ListItemText primary={label} secondary={subtitle} />
            {locale === value && (
              <CheckRounded color="primary" sx={{ fontSize: 18 }} />
            )}
          </MenuItem>
        ))}
      </Menu>
    </>
  );
}
