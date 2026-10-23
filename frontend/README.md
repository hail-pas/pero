# Pero frontend

React + TypeScript 7 + Vite 8 + MUI 9. Visual foundations come from [Minimal Free](https://free.minimals.cc/) and its [MIT source](https://github.com/minimal-ui-kit/material-kit-react) (package version 3.0.0, retrieved 2026-10-22). `src/theme`, `src/components/label`, `src/components/svg-color`, and navbar SVGs retain that design system; see `LICENSE.minimal.md`. Numeric border-radius casts adapt upstream code to the installed MUI types.

## Development

Node.js 24.11+ and pnpm 11.25:

```sh
pnpm install --frozen-lockfile
pnpm dev
```

Start Rust separately. Requests go to `http://127.0.0.1:8080`; override with `PERO_API_ORIGIN`. Open `http://127.0.0.1:3039`. OAuth callbacks and cookies remain owned by Rust. For a full OAuth flow, build once with `bash scripts/build-frontend.sh` from the repository root so protocol-driven navigation can also load the built application from Rust.

## Production

Run `bash scripts/build-frontend.sh` from the repository root. It builds `dist/` and copies the same output into both services. Rust serves the build at `/static/`; set `[frontend].static_dir` to that directory in deployment configuration. Docker performs this build automatically. Build output and `node_modules` are ignored by Git.

## Code

- `app.tsx`: route data loading, redirects and mutation state.
- `page-content.tsx`: exhaustive dispatch by the response view.
- `action-dialog.tsx`: confirmation, editing and generated-secret dialogs.
- `contracts.ts`: concrete response DTOs and the discriminated view/data union.
- `account.tsx`, `management.tsx`, `management-form.tsx`, `auth.tsx`, `home.tsx`: business interfaces.
- `layout.tsx`, `shared.tsx`, `forms.tsx`: common navigation, components, forms.
- `components/identity-graphic.tsx`: original rounded-square orbital graphic shared by the homepage and authentication, with a compact rotated authentication variant.
- `security.tsx`: sessions, sign-in activity, application consent, linked accounts and administrative audit pages.
- `api.ts`: HTTP transport, CSRF form submission, error messages and dates.
- `tests/platform.spec.ts`: browser UI regressions with explicit API fixtures.
- `tests/backend-logout.cjs`: real Rust/PostgreSQL/Redis browser integration, invoked by Rust's logout test.

Page endpoints return `{ view, data }` when requested with `Accept: application/json`. JSON clients receive `{ redirect }` instead of an HTTP redirect, preserving OAuth navigation and cookies without cross-origin fetches. All server-side authorization and CSRF checks run before data is returned. No secrets or session tokens are stored in localStorage.

## Checks

```sh
pnpm build
pnpm exec playwright install chromium
pnpm test
```

## Languages

Chinese and English are available from the language control on public pages, authentication pages, and the workspace header. The initial language follows the browser; the selection is persisted in `pero.lang` and synchronized across tabs. Switching languages preserves routes and unsaved form input. MUI labels and backend error messages follow the selected language, and requests include the selected `Accept-Language`.

`src/i18n.tsx` provides the locale context and interpolation. Product messages use their Chinese source text as catalogue keys, with English translations in `src/locales/en.json`. The catalogue check uses `@babel/parser` to read TypeScript and JSX source strings. Business data such as user names and application descriptions is preserved. Add translations to this catalogue when adding product text; the catalogue regression test checks coverage and interpolation parameters.
