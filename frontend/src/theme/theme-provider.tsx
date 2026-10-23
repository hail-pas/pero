import { enUS, zhCN } from "@mui/material/locale";
import type { ThemeProviderProps as MuiThemeProviderProps } from "@mui/material/styles";
import { useMemo } from "react";
import { useLocale } from "../i18n";

import CssBaseline from "@mui/material/CssBaseline";
import { ThemeProvider as ThemeVarsProvider } from "@mui/material/styles";

import { createTheme } from "./create-theme";

import type {} from "./extend-theme-types";
import type { ThemeOptions } from "./types";

// ----------------------------------------------------------------------

export type ThemeProviderProps = Partial<MuiThemeProviderProps> & {
  themeOverrides?: ThemeOptions;
};

export function ThemeProvider({
  themeOverrides,
  children,
  ...other
}: ThemeProviderProps) {
  const { locale } = useLocale();
  const theme = useMemo(
    () =>
      createTheme({
        themeOverrides: {
          ...(locale === "en" ? enUS : zhCN),
          ...themeOverrides,
        },
      }),
    [locale, themeOverrides],
  );

  return (
    <ThemeVarsProvider disableTransitionOnChange theme={theme} {...other}>
      <CssBaseline />
      {children}
    </ThemeVarsProvider>
  );
}
