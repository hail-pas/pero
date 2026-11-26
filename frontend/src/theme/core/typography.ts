import type {
  Breakpoint,
  CSSObject,
  TypographyVariantsOptions,
} from "@mui/material/styles";

import { pxToRem, setFont } from "minimal-shared/utils";

import { createTheme as getTheme } from "@mui/material/styles";

import { themeConfig } from "../theme-config";

// ----------------------------------------------------------------------

/**
 * TypeScript (type definition and extension)
 * @to {@link file://./../extend-theme-types.d.ts}
 */
export type FontStyleExtend = {
  fontWeightSemiBold: CSSObject["fontWeight"];
  fontSecondaryFamily: CSSObject["fontFamily"];
};

export type ResponsiveFontSizesInput = Partial<Record<Breakpoint, number>>;
export type ResponsiveFontSizesResult = Record<string, { fontSize: string }>;

const defaultMuiTheme = getTheme();

function responsiveFontSizes(
  obj: ResponsiveFontSizesInput,
): ResponsiveFontSizesResult {
  const breakpoints: Breakpoint[] = defaultMuiTheme.breakpoints.keys;

  return breakpoints.reduce((acc, breakpoint) => {
    const value = obj[breakpoint];

    if (value !== undefined && value >= 0) {
      acc[defaultMuiTheme.breakpoints.up(breakpoint)] = {
        fontSize: pxToRem(value),
      };
    }

    return acc;
  }, {} as ResponsiveFontSizesResult);
}

// ----------------------------------------------------------------------

// Latin text uses the Minimal typefaces; CJK text falls back to the platform's
// native UI fonts so mixed copy keeps consistent weight and rhythm.
const cjkFallback =
  '"PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Noto Sans SC", sans-serif';
const primaryFont = `${setFont(themeConfig.fontFamily.primary).replace(/,\s*sans-serif$/, "")}, ${cjkFallback}`;
const secondaryFont = `${setFont(themeConfig.fontFamily.secondary).replace(/,\s*sans-serif$/, "")}, ${cjkFallback}`;

export const typography: TypographyVariantsOptions = {
  fontFamily: primaryFont,
  fontSecondaryFamily: secondaryFont,
  fontWeightLight: "300",
  fontWeightRegular: "400",
  fontWeightMedium: "500",
  fontWeightSemiBold: "600",
  fontWeightBold: "700",
  h1: {
    fontFamily: secondaryFont,
    fontWeight: 800,
    lineHeight: 1.08,
    letterSpacing: "-0.03em",
    fontSize: pxToRem(40),
    ...responsiveFontSizes({ sm: 52, md: 58, lg: 64 }),
  },
  h2: {
    fontFamily: secondaryFont,
    fontWeight: 800,
    lineHeight: 1.16,
    letterSpacing: "-0.025em",
    fontSize: pxToRem(32),
    ...responsiveFontSizes({ sm: 40, md: 44, lg: 48 }),
  },
  h3: {
    fontFamily: secondaryFont,
    fontWeight: 700,
    lineHeight: 1.25,
    letterSpacing: "-0.02em",
    fontSize: pxToRem(24),
    ...responsiveFontSizes({ sm: 26, md: 30, lg: 32 }),
  },
  h4: {
    fontWeight: 700,
    lineHeight: 1.3,
    letterSpacing: "-0.02em",
    fontSize: pxToRem(21),
    ...responsiveFontSizes({ md: 24 }),
  },
  h5: {
    fontWeight: 700,
    lineHeight: 1.4,
    letterSpacing: "-0.01em",
    fontSize: pxToRem(18),
    ...responsiveFontSizes({ sm: 19 }),
  },
  h6: {
    fontWeight: 600,
    lineHeight: 28 / 18,
    letterSpacing: "-0.01em",
    fontSize: pxToRem(16),
    ...responsiveFontSizes({ sm: 17 }),
  },
  subtitle1: {
    fontWeight: 600,
    lineHeight: 1.5,
    fontSize: pxToRem(16),
  },
  subtitle2: {
    fontWeight: 600,
    lineHeight: 22 / 14,
    fontSize: pxToRem(14),
  },
  body1: {
    lineHeight: 1.5,
    fontSize: pxToRem(16),
  },
  body2: {
    lineHeight: 22 / 14,
    fontSize: pxToRem(14),
  },
  caption: {
    lineHeight: 1.5,
    fontSize: pxToRem(12),
  },
  overline: {
    fontWeight: 700,
    lineHeight: 1.5,
    fontSize: pxToRem(12),
    textTransform: "uppercase",
  },
  button: {
    fontWeight: 700,
    lineHeight: 24 / 14,
    fontSize: pxToRem(14),
    textTransform: "unset",
  },
};
