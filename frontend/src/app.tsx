import { RefreshRounded } from "@mui/icons-material";
import {
  Alert,
  Button,
  Card,
  CardContent,
  Box,
  LinearProgress,
  Snackbar,
} from "@mui/material";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  redirect,
  redirectDocument,
  ScrollRestoration,
  useLoaderData,
  useLocation,
  useNavigate,
  useNavigation,
  useRevalidator,
  type LoaderFunctionArgs,
} from "react-router-dom";
import { errorText, request, type ViewEnvelope, type Values } from "./api";
import type { Field } from "./forms";
import { ActionDialog, type ActionModal } from "./action-dialog";
import { t, useLocale } from "./i18n";
import { Layout } from "./layout";
import { PageContent } from "./page-content";

function documentNavigation(url: URL) {
  return (
    url.origin !== window.location.origin ||
    url.pathname.startsWith("/oauth2") ||
    (url.pathname.includes("/social/") && !url.pathname.endsWith("/link"))
  );
}

// The router commits a location only after the server has resolved access and
// redirects. Existing content and its layout stay mounted while this runs.
let loaderSequence = 0;
export async function pageLoader({ request: navigation }: LoaderFunctionArgs) {
  const sequence = ++loaderSequence;
  try {
    const url = new URL(navigation.url);
    const result = await request(
      url.pathname + url.search,
      undefined,
      navigation.signal,
    );
    if (!result.view && result.redirect) {
      const target = new URL(result.redirect, window.location.origin);
      return documentNavigation(target)
        ? redirectDocument(target.href)
        : redirect(target.pathname + target.search);
    }
    if (!result.view) throw new Error(errorText("invalid_response"));
    return { payload: result, failure: "", sequence };
  } catch (error) {
    if (navigation.signal.aborted) throw error;
    return { payload: undefined, failure: (error as Error).message, sequence };
  }
}

export function InitialLoading() {
  return (
    <Box
      sx={{
        position: "fixed",
        inset: "0 0 auto",
        height: 3,
        zIndex: (theme) => theme.zIndex.modal + 1,
      }}
    >
      <LinearProgress aria-label={t("正在加载")} />
    </Box>
  );
}

export function App() {
  const { locale } = useLocale();
  const location = useLocation(),
    navigate = useNavigate();
  const loaded = useLoaderData<typeof pageLoader>();
  const pendingRequests = useRef(0);
  const navigation = useNavigation();
  const revalidator = useRevalidator();
  const activeRoute = useRef({ key: location.key });
  if (activeRoute.current.key !== location.key) {
    activeRoute.current = { key: location.key };
  }
  const [updated, setUpdated] = useState<{
    sequence: number;
    route: typeof activeRoute.current;
    payload: ViewEnvelope;
  }>();
  // A GET started before a mutation completed must not replace its newer view,
  // especially when that response contains one-time recovery credentials.
  const currentUpdate =
    updated?.route === activeRoute.current &&
    updated.sequence >= loaded.sequence
      ? updated
      : undefined;
  const payload = currentUpdate?.payload ?? loaded.payload;
  const failure = currentUpdate ? "" : loaded.failure;
  const routeKey = location.pathname + location.search;
  const [notice, setNotice] = useState("");
  const [pendingNotice, setPendingNotice] = useState<{
    sourceKey: string;
    text: string;
  }>();
  useEffect(() => {
    if (navigation.state !== "idle") setNotice("");
    else if (pendingNotice && location.key !== pendingNotice.sourceKey) {
      // Navigation callbacks can resolve before React commits their destination.
      setNotice(pendingNotice.text);
      setPendingNotice(undefined);
    }
  }, [navigation.state, location.key, pendingNotice]);
  const [modalState, setModalState] = useState<{
    route: typeof activeRoute.current;
    value: ActionModal | null;
  }>();
  const modal =
    modalState?.route === activeRoute.current ? modalState.value : null;
  const setModal = (value: ActionModal | null) =>
    setModalState({ route: activeRoute.current, value });
  const [showProgress, setShowProgress] = useState(false);
  const busy = navigation.state !== "idle" || revalidator.state !== "idle";
  useEffect(() => {
    if (!busy) {
      setShowProgress(false);
      return;
    }
    const timer = window.setTimeout(() => setShowProgress(true), 180);
    return () => window.clearTimeout(timer);
  }, [busy]);
  const setPayload = (next: ViewEnvelope) =>
    setUpdated({
      sequence: loaderSequence,
      route: activeRoute.current,
      payload: next,
    });
  const refresh = () => revalidator.revalidate();
  const csrfToken =
    payload?.data && "csrf_token" in payload.data
      ? payload.data.csrf_token
      : "";
  const layout =
    payload?.data && "layout" in payload.data ? payload.data.layout : undefined;
  const path = location.pathname;
  const showingRecoveryCodes =
    payload?.view === "SecurityView" && payload.data.codes.length > 0;
  // Re-read server permissions when returning from another tab or application.
  useEffect(() => {
    const revalidate = () => {
      if (
        document.visibilityState === "visible" &&
        navigation.state === "idle" &&
        revalidator.state === "idle" &&
        !modal &&
        pendingRequests.current === 0 &&
        !showingRecoveryCodes &&
        (path === "/" ||
          path.startsWith("/account") ||
          path.startsWith("/dashboard"))
      ) {
        revalidator.revalidate();
      }
    };
    window.addEventListener("focus", revalidate);
    document.addEventListener("visibilitychange", revalidate);
    return () => {
      window.removeEventListener("focus", revalidate);
      document.removeEventListener("visibilitychange", revalidate);
    };
  }, [path, navigation.state, revalidator, modal, showingRecoveryCodes]);

  const follow = useCallback(
    (target: string) => {
      const url = new URL(target, window.location.origin);
      if (documentNavigation(url)) window.location.assign(url.href);
      else return navigate(url.pathname + url.search, { replace: true });
    },
    [navigate],
  );
  useEffect(() => {
    document.title = t("Pero · {{0}}", {
      "0": t(
        path.startsWith("/dashboard")
          ? "管理控制台"
          : path.startsWith("/account")
            ? "个人中心"
            : "用户中心",
      ),
    });
  }, [path, locale]);
  function clearViewError() {
    if (payload?.data && "error" in payload.data && payload.data.error) {
      setPayload({
        ...payload,
        data: { ...payload.data, error: "" },
      } as ViewEnvelope);
    }
  }
  async function mutate(
    endpoint: string,
    values: Values = {},
    after?: () => void,
  ) {
    const sourceRoute = activeRoute.current;
    setNotice("");
    setPendingNotice(undefined);
    if (payload?.view === "ForgotPasswordView") {
      setPayload({
        ...payload,
        data: { ...payload.data, error: "", success: false },
      });
    } else {
      clearViewError();
    }
    let result;
    pendingRequests.current++;
    try {
      result = await request(endpoint, { ...values, csrf_token: csrfToken });
    } catch (error) {
      if (activeRoute.current !== sourceRoute) return;
      if ((error as Error & { code?: string }).code === "forbidden") {
        setModal(null);
        setPayload({ view: "ForbiddenView", data: { code: "forbidden" } });
      }
      throw error;
    } finally {
      pendingRequests.current--;
    }
    if (activeRoute.current !== sourceRoute) return;
    if (!result.view && result.redirect) {
      await follow(result.redirect);
      return;
    }
    if (
      !result.view &&
      result.data &&
      "secret" in result.data &&
      result.data.secret
    ) {
      setModal({
        kind: "secret",
        label:
          result.data.purpose === "mfa_recovery"
            ? t("临时恢复码")
            : t("客户端密钥"),
        title:
          result.data.purpose === "mfa_recovery"
            ? t("临时恢复码")
            : t("请保存客户端密钥"),
        description:
          result.data.purpose === "mfa_recovery"
            ? t(
                "恢复码仅显示一次，15 分钟内有效。核验身份后私下交付本人；用户须先登录，再使用恢复码重新绑定验证器。",
              )
            : t("密钥只在此时显示，请复制并妥善保存。"),
        secret: result.data.secret,
      });
      return;
    }
    if (result.view) {
      // A view response owns its feedback and latest state, including expired
      // MFA setup or recovery transitions. JSON action errors reject above.
      setModal(null);
      setPayload(result);
      return;
    }
    setModal(null);
    if (after) {
      await after();
      setPendingNotice({ sourceKey: sourceRoute.key, text: t("操作已完成") });
    } else {
      setNotice(t("操作已完成"));
      await refresh();
    }
  }
  function ask(
    title: string,
    endpoint: string,
    values: Values = {},
    description = t("此操作会立即生效，请确认后继续。"),
  ) {
    setModal({ kind: "confirm", title, endpoint, values, description });
  }
  function editor(
    title: string,
    endpoint: string,
    fields: Field[],
    initial: Values = {},
    values: Values = {},
  ) {
    setModal({ kind: "editor", title, endpoint, fields, initial, values });
  }
  const actions = { mutate, ask, editor };
  let content: React.ReactNode;
  if (failure)
    content = (
      <Card>
        <CardContent>
          <Alert severity="error">{t(failure)}</Alert>
          <Button
            sx={{ mt: 2 }}
            onClick={refresh}
            startIcon={<RefreshRounded />}
          >
            {t("重新加载")}
          </Button>
        </CardContent>
      </Card>
    );
  else if (payload)
    content = (
      <PageContent
        key={routeKey + payload.view}
        page={payload}
        actions={actions}
        follow={follow}
      />
    );
  content = (
    <Box
      inert={navigation.state !== "idle"}
      aria-busy={busy}
      onChangeCapture={clearViewError}
    >
      {content}
    </Box>
  );
  const authenticationStep =
    payload?.view === "SecurityView" &&
    (payload.data.pending ||
      payload.data.recovery ||
      (payload.data.required && !payload.data.enabled) ||
      path === "/sso/mfa");
  const managed =
    !!layout &&
    !authenticationStep &&
    (path.startsWith("/dashboard") ||
      payload?.view === "SecurityView" ||
      (path.startsWith("/account") && !path.endsWith("/login")));
  return (
    <>
      <ScrollRestoration />
      {showProgress && <InitialLoading />}
      {managed ? (
        <Layout
          layout={layout ?? undefined}
          onLogout={() =>
            ask(
              t("退出登录"),
              "/account/logout",
              {},
              t("退出当前账户并撤销当前登录会话。"),
            )
          }
        >
          {content}
        </Layout>
      ) : (
        <>{content}</>
      )}
      <Snackbar
        open={!!notice}
        autoHideDuration={4000}
        onClose={() => setNotice("")}
      >
        <Alert severity="success" onClose={() => setNotice("")}>
          {t(notice)}
        </Alert>
      </Snackbar>
      {modal && (
        <ActionDialog
          key={
            modal.kind === "secret" ? modal.kind : modal.kind + modal.endpoint
          }
          modal={modal}
          mutate={mutate}
          onClose={() => {
            setModal(null);
            if (modal.kind === "secret") refresh();
          }}
        />
      )}
    </>
  );
}
