import type { Components, Theme } from "@mui/material/styles";

import { varAlpha } from "minimal-shared/utils";

import SvgIcon from "@mui/material/SvgIcon";

// ----------------------------------------------------------------------

const hairline = (theme: Theme) =>
  varAlpha(theme.vars.palette.grey["500Channel"], 0.16);

const MuiBackdrop: Components<Theme>["MuiBackdrop"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      backgroundColor: varAlpha(theme.vars.palette.grey["900Channel"], 0.64),
      backdropFilter: "blur(2px)",
    }),
    invisible: {
      background: "transparent",
    },
  },
};

const MuiButton: Components<Theme>["MuiButton"] = {
  defaultProps: {
    disableElevation: true,
  },
  styleOverrides: {
    root: ({ theme }) => ({
      borderRadius: Number(theme.shape.borderRadius) * 1.25,
      fontWeight: theme.typography.fontWeightSemiBold,
      transition: theme.transitions.create(
        ["background-color", "border-color", "color", "box-shadow"],
        { duration: theme.transitions.duration.shorter },
      ),
      variants: [
        {
          props: { variant: "contained", color: "inherit" },
          style: {
            color: theme.vars.palette.common.white,
            backgroundColor: theme.vars.palette.grey[800],
            "&:hover": {
              color: theme.vars.palette.common.white,
              backgroundColor: theme.vars.palette.grey[900],
            },
          },
        },
        {
          props: { variant: "contained", color: "primary" },
          style: {
            boxShadow: `0 1px 2px 0 ${varAlpha(theme.vars.palette.primary.mainChannel, 0.24)}`,
            "&:hover": {
              boxShadow: `0 4px 12px -2px ${varAlpha(theme.vars.palette.primary.mainChannel, 0.32)}`,
            },
          },
        },
        {
          props: { variant: "outlined", color: "inherit" },
          style: {
            borderColor: hairline(theme),
            color: theme.vars.palette.text.primary,
            "&:hover": {
              borderColor: varAlpha(theme.vars.palette.grey["500Channel"], 0.32),
              backgroundColor: varAlpha(
                theme.vars.palette.grey["500Channel"],
                0.04,
              ),
            },
          },
        },
        {
          props: { variant: "text", color: "inherit" },
          style: {
            color: theme.vars.palette.text.secondary,
            "&:hover": {
              color: theme.vars.palette.text.primary,
              backgroundColor: varAlpha(
                theme.vars.palette.grey["500Channel"],
                0.08,
              ),
            },
          },
        },
      ],
    }),
    sizeSmall: {
      minHeight: 34,
      paddingInline: 12,
      fontSize: 13,
    },
    sizeMedium: {
      minHeight: 40,
      paddingInline: 16,
    },
    sizeLarge: {
      minHeight: 48,
      paddingInline: 22,
      fontSize: 15,
    },
  },
};

const MuiIconButton: Components<Theme>["MuiIconButton"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      borderRadius: Number(theme.shape.borderRadius) * 1.25,
    }),
  },
};

const MuiCard: Components<Theme>["MuiCard"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      zIndex: 0,
      position: "relative",
      borderRadius: Number(theme.shape.borderRadius) * 2,
      border: `1px solid ${hairline(theme)}`,
      boxShadow: `0 1px 2px 0 ${varAlpha(theme.vars.palette.grey["900Channel"], 0.04)}`,
    }),
  },
};

const MuiCardHeader: Components<Theme>["MuiCardHeader"] = {
  defaultProps: {
    slotProps: {
      title: { variant: "h6" },
      subheader: { variant: "body2" },
    },
  },
  styleOverrides: {
    root: ({ theme }) => ({
      padding: theme.spacing(3, 3, 0),
    }),
  },
};

const MuiCardContent: Components<Theme>["MuiCardContent"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      padding: theme.spacing(3),
      "&:last-child": { paddingBottom: theme.spacing(3) },
    }),
  },
};

const MuiOutlinedInput: Components<Theme>["MuiOutlinedInput"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      borderRadius: Number(theme.shape.borderRadius) * 1.25,
      backgroundColor: theme.vars.palette.background.paper,
      transition: theme.transitions.create(["box-shadow", "border-color"], {
        duration: theme.transitions.duration.shorter,
      }),
      "& .MuiOutlinedInput-notchedOutline": {
        borderColor: varAlpha(theme.vars.palette.grey["500Channel"], 0.24),
      },
      "&:hover .MuiOutlinedInput-notchedOutline": {
        borderColor: varAlpha(theme.vars.palette.grey["500Channel"], 0.4),
      },
      "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
        borderWidth: 1,
      },
      "&.Mui-focused": {
        boxShadow: `0 0 0 3px ${varAlpha(theme.vars.palette.primary.mainChannel, 0.12)}`,
      },
    }),
  },
};

const MuiInputLabel: Components<Theme>["MuiInputLabel"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      fontSize: theme.typography.pxToRem(14),
    }),
  },
};

const MuiSelect: Components<Theme>["MuiSelect"] = {
  styleOverrides: {
    select: {
      minWidth: 0,
      whiteSpace: "normal",
      overflowWrap: "anywhere",
    },
  },
};

const MuiFormHelperText: Components<Theme>["MuiFormHelperText"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      marginTop: theme.spacing(0.75),
      lineHeight: 1.5,
    }),
  },
};

const MuiPaper: Components<Theme>["MuiPaper"] = {
  defaultProps: { elevation: 0 },
  styleOverrides: {
    root: { backgroundImage: "none" },
    outlined: ({ theme }) => ({
      borderColor: hairline(theme),
    }),
    rounded: ({ theme }) => ({
      borderRadius: Number(theme.shape.borderRadius) * 1.5,
    }),
  },
};

const MuiTableCell: Components<Theme>["MuiTableCell"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      fontSize: theme.typography.pxToRem(14),
      padding: theme.spacing(1.5, 2),
      borderBottom: `1px solid ${hairline(theme)}`,
      "&:first-of-type": { paddingLeft: theme.spacing(3) },
      "&:last-of-type": { paddingRight: theme.spacing(3) },
    }),
    head: ({ theme }) => ({
      color: theme.vars.palette.text.secondary,
      fontWeight: theme.typography.fontWeightSemiBold,
      fontSize: theme.typography.pxToRem(12),
      letterSpacing: "0.04em",
      textTransform: "uppercase",
      backgroundColor: theme.vars.palette.background.neutral,
      height: 44,
      whiteSpace: "nowrap",
    }),
    sizeSmall: ({ theme }) => ({
      padding: theme.spacing(1, 1.5),
    }),
  },
};

const MuiTableRow: Components<Theme>["MuiTableRow"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      transition: theme.transitions.create("background-color", {
        duration: theme.transitions.duration.shortest,
      }),
      "&:last-of-type td": { borderBottom: 0 },
    }),
  },
};

const MuiMenuItem: Components<Theme>["MuiMenuItem"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      ...theme.typography.body2,
      borderRadius: Number(theme.shape.borderRadius),
      minHeight: 38,
      marginInline: theme.spacing(0.5),
      '&[role="option"]': {
        whiteSpace: "normal",
        overflowWrap: "anywhere",
      },
      "&.Mui-selected": {
        fontWeight: theme.typography.fontWeightSemiBold,
      },
    }),
  },
};

const MuiMenu: Components<Theme>["MuiMenu"] = {
  styleOverrides: {
    paper: ({ theme }) => ({
      borderRadius: Number(theme.shape.borderRadius) * 1.5,
      border: `1px solid ${hairline(theme)}`,
      boxShadow: theme.vars.customShadows.dropdown,
      padding: theme.spacing(0.75, 0),
      marginTop: theme.spacing(0.5),
    }),
  },
};

const MuiPopover: Components<Theme>["MuiPopover"] = {
  styleOverrides: {
    paper: ({ theme }) => ({
      borderRadius: Number(theme.shape.borderRadius) * 1.5,
      border: `1px solid ${hairline(theme)}`,
      boxShadow: theme.vars.customShadows.dropdown,
    }),
  },
};

const MuiLink: Components<Theme>["MuiLink"] = {
  defaultProps: { underline: "hover" },
  styleOverrides: {
    root: { fontWeight: 500 },
  },
};

const MuiFormControlLabel: Components<Theme>["MuiFormControlLabel"] = {
  styleOverrides: {
    label: ({ theme }) => ({
      ...theme.typography.body2,
    }),
  },
};

const MuiCheckbox: Components<Theme>["MuiCheckbox"] = {
  defaultProps: {
    size: "small",
    icon: (
      <SvgIcon>
        <path d="M17.9 2.318A5 5 0 0 1 22.895 7.1l.005.217v10a5 5 0 0 1-4.783 4.995l-.217.005h-10a5 5 0 0 1-4.995-4.783l-.005-.217v-10a5 5 0 0 1 4.783-4.996l.217-.004h10Zm-.5 1.5h-9a4 4 0 0 0-4 4v9a4 4 0 0 0 4 4h9a4 4 0 0 0 4-4v-9a4 4 0 0 0-4-4Z" />
      </SvgIcon>
    ),
    checkedIcon: (
      <SvgIcon>
        <path d="M17 2a5 5 0 0 1 5 5v10a5 5 0 0 1-5 5H7a5 5 0 0 1-5-5V7a5 5 0 0 1 5-5Zm-1.625 7.255-4.13 4.13-1.75-1.75a.881.881 0 0 0-1.24 0c-.34.34-.34.89 0 1.24l2.38 2.37c.17.17.39.25.61.25.23 0 .45-.08.62-.25l4.75-4.75c.34-.34.34-.89 0-1.24a.881.881 0 0 0-1.24 0Z" />
      </SvgIcon>
    ),
    indeterminateIcon: (
      <SvgIcon>
        <path d="M17,2 C19.7614,2 22,4.23858 22,7 L22,7 L22,17 C22,19.7614 19.7614,22 17,22 L17,22 L7,22 C4.23858,22 2,19.7614 2,17 L2,17 L2,7 C2,4.23858 4.23858,2 7,2 L7,2 Z M15,11 L9,11 C8.44772,11 8,11.4477 8,12 C8,12.5523 8.44772,13 9,13 L15,13 C15.5523,13 16,12.5523 16,12 C16,11.4477 15.5523,11 15,11 Z" />
      </SvgIcon>
    ),
  },
};

const MuiRadio: Components<Theme>["MuiRadio"] = {
  defaultProps: {
    size: "small",
    icon: (
      <SvgIcon>
        <path
          d="M12 2C13.9778 2 15.9112 2.58649 17.5557 3.6853C19.2002 4.78412 20.4819 6.3459 21.2388 8.17317C21.9957 10.0004 22.1937 12.0111 21.8079 13.9509C21.422 15.8907 20.4696 17.6725 19.0711 19.0711C17.6725 20.4696 15.8907 21.422 13.9509 21.8079C12.0111 22.1937 10.0004 21.9957 8.17317 21.2388C6.3459 20.4819 4.78412 19.2002 3.6853 17.5557C2.58649 15.9112 2 13.9778 2 12C2 6.477 6.477 2 12 2ZM12 3.5C9.74566 3.5 7.58365 4.39553 5.98959 5.98959C4.39553 7.58365 3.5 9.74566 3.5 12C3.5 14.2543 4.39553 16.4163 5.98959 18.0104C7.58365 19.6045 9.74566 20.5 12 20.5C14.2543 20.5 16.4163 19.6045 18.0104 18.0104C19.6045 16.4163 20.5 14.2543 20.5 12C20.5 9.74566 19.6045 7.58365 18.0104 5.98959C16.4163 4.39553 14.2543 3.5 12 3.5Z"
          fill="currentColor"
        />
      </SvgIcon>
    ),
    checkedIcon: (
      <SvgIcon>
        <path
          fillRule="evenodd"
          clipRule="evenodd"
          d="M12 2C6.477 2 2 6.477 2 12C2 17.523 6.477 22 12 22C17.523 22 22 17.523 22 12C22 6.477 17.523 2 12 2ZM12 8C10.9391 8 9.92172 8.42143 9.17157 9.17157C8.42143 9.92172 8 10.9391 8 12C8 13.0609 8.42143 14.0783 9.17157 14.8284C9.92172 15.5786 10.9391 16 12 16C13.0609 16 14.0783 15.5786 14.8284 14.8284C15.5786 14.0783 16 13.0609 16 12C16 10.9391 15.5786 9.92172 14.8284 9.17157C14.0783 8.42143 13.0609 8 12 8Z"
          fill="currentColor"
        />
      </SvgIcon>
    ),
  },
};

const MuiChip: Components<Theme>["MuiChip"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      borderRadius: Number(theme.shape.borderRadius),
      fontWeight: theme.typography.fontWeightSemiBold,
      fontSize: theme.typography.pxToRem(12),
      height: 26,
    }),
    label: {
      paddingInline: 10,
    },
  },
};

const MuiAlert: Components<Theme>["MuiAlert"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      borderRadius: Number(theme.shape.borderRadius) * 1.25,
      padding: theme.spacing(1.25, 2),
      alignItems: "center",
    }),
    message: {
      paddingBlock: 2,
    },
  },
};

const MuiDialog: Components<Theme>["MuiDialog"] = {
  styleOverrides: {
    paper: ({ theme }) => ({
      borderRadius: Number(theme.shape.borderRadius) * 2,
      boxShadow: theme.vars.customShadows.dialog,
    }),
  },
};

const MuiDialogTitle: Components<Theme>["MuiDialogTitle"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      ...theme.typography.h5,
      padding: theme.spacing(3, 3, 1),
    }),
  },
};

const MuiDialogContent: Components<Theme>["MuiDialogContent"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      padding: theme.spacing(2, 3),
    }),
  },
};

const MuiDialogActions: Components<Theme>["MuiDialogActions"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      padding: theme.spacing(2, 3, 3),
      gap: theme.spacing(1),
    }),
  },
};

const MuiAccordion: Components<Theme>["MuiAccordion"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      borderRadius: Number(theme.shape.borderRadius) * 1.5,
      border: `1px solid ${hairline(theme)}`,
      boxShadow: "none",
      "&:before": { display: "none" },
      "&.Mui-expanded": { margin: 0 },
    }),
  },
};

const MuiAccordionSummary: Components<Theme>["MuiAccordionSummary"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      minHeight: 52,
      paddingInline: theme.spacing(2.5),
      "&.Mui-expanded": { minHeight: 52 },
    }),
  },
};

const MuiAccordionDetails: Components<Theme>["MuiAccordionDetails"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      padding: theme.spacing(0, 2.5, 2.5),
    }),
  },
};

const MuiPaginationItem: Components<Theme>["MuiPaginationItem"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      borderRadius: Number(theme.shape.borderRadius),
      fontWeight: theme.typography.fontWeightMedium,
    }),
  },
};

const MuiTooltip: Components<Theme>["MuiTooltip"] = {
  styleOverrides: {
    tooltip: ({ theme }) => ({
      backgroundColor: theme.vars.palette.grey[800],
      borderRadius: Number(theme.shape.borderRadius),
      fontSize: theme.typography.pxToRem(12),
      padding: theme.spacing(0.75, 1.25),
    }),
  },
};

const MuiAvatar: Components<Theme>["MuiAvatar"] = {
  styleOverrides: {
    root: {
      fontWeight: 600,
      fontSize: "0.875rem",
    },
  },
};

const MuiLinearProgress: Components<Theme>["MuiLinearProgress"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      borderRadius: 999,
      backgroundColor: varAlpha(theme.vars.palette.primary.mainChannel, 0.08),
    }),
    bar: {
      borderRadius: 999,
    },
  },
};

const MuiListItemButton: Components<Theme>["MuiListItemButton"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      borderRadius: Number(theme.shape.borderRadius) * 1.25,
      transition: theme.transitions.create(["background-color", "color"], {
        duration: theme.transitions.duration.shortest,
      }),
    }),
  },
};

const MuiDivider: Components<Theme>["MuiDivider"] = {
  styleOverrides: {
    root: ({ theme }) => ({
      borderColor: hairline(theme),
    }),
  },
};

// ----------------------------------------------------------------------

export const components = {
  MuiCard,
  MuiLink,
  MuiMenu,
  MuiPaper,
  MuiRadio,
  MuiSelect,
  MuiAlert,
  MuiButton,
  MuiDialog,
  MuiDivider,
  MuiAccordion,
  MuiBackdrop,
  MuiCardHeader,
  MuiCardContent,
  MuiCheckbox,
  MuiChip,
  MuiMenuItem,
  MuiPopover,
  MuiAvatar,
  MuiIconButton,
  MuiTableCell,
  MuiTableRow,
  MuiTooltip,
  MuiDialogTitle,
  MuiInputLabel,
  MuiOutlinedInput,
  MuiDialogActions,
  MuiDialogContent,
  MuiPaginationItem,
  MuiLinearProgress,
  MuiListItemButton,
  MuiFormHelperText,
  MuiAccordionSummary,
  MuiAccordionDetails,
  MuiFormControlLabel,
};
