import type { Theme } from "@mui/material/styles";

import { createTheme as createMuiTheme } from "@mui/material/styles";

import { components } from "./core/components";
import { customShadows } from "./core/custom-shadows";
import { palette } from "./core/palette";
import { shadows } from "./core/shadows";
import { typography } from "./core/typography";
import { themeConfig } from "./theme-config";

import type { ThemeOptions } from "./types";

// ----------------------------------------------------------------------

export const baseTheme: ThemeOptions = {
  colorSchemes: {
    light: {
      palette: palette.light,
      shadows: shadows.light,
      customShadows: customShadows.light,
    },
  },
  components,
  typography,
  shape: { borderRadius: 8 },
  cssVariables: themeConfig.cssVariables,
};

// ----------------------------------------------------------------------

type CreateThemeProps = {
  themeOverrides?: ThemeOptions;
};

export function createTheme({
  themeOverrides = {},
}: CreateThemeProps = {}): Theme {
  const theme = createMuiTheme(baseTheme, themeOverrides);

  return theme;
}
