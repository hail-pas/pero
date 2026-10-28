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
export async function pageLoader({ request: navigation }: LoaderFunctionArgs) {
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
    return { payload: result, failure: "" };
  } catch (error) {
    if (navigation.signal.aborted) throw error;
    return { payload: undefined, failure: (error as Error).message };
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
  const navigation = useNavigation();
  const revalidator = useRevalidator();
  const [updated, setUpdated] = useState<{
    source: typeof loaded;
    payload: ViewEnvelope;
  }>();
  const payload = updated?.source === loaded ? updated.payload : loaded.payload;
  const failure = loaded.failure;
  const routeKey = location.pathname + location.search;
  const [noticeState, setNoticeState] = useState({ routeKey, text: "" });
  const notice = noticeState.routeKey === routeKey ? noticeState.text : "";
  const setNotice = (text: string) => setNoticeState({ routeKey, text });
  const [modalState, setModalState] = useState<{
    routeKey: string;
    value: ActionModal | null;
  }>();
  const modal = modalState?.routeKey === routeKey ? modalState.value : null;
  const setModal = (value: ActionModal | null) =>
    setModalState({ routeKey, value });
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
  const activeRoute = useRef(routeKey);
  activeRoute.current = routeKey;
  const setPayload = (next: ViewEnvelope) =>
    setUpdated({ source: loaded, payload: next });
  const refresh = () => revalidator.revalidate();
  const csrfToken =
    payload?.data && "csrf_token" in payload.data
      ? payload.data.csrf_token
      : "";
  const layout =
    payload?.data && "layout" in payload.data ? payload.data.layout : undefined;
  const path = location.pathname;
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
  async function mutate(
    endpoint: string,
    values: Values = {},
    after?: () => void,
  ) {
    const sourceRoute = routeKey;
    const result = await request(endpoint, {
      ...values,
      csrf_token: csrfToken,
    });
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
        title: t("请保存客户端密钥"),
        description: t("密钥只在此时显示，请复制并妥善保存。"),
        secret: result.data.secret,
      });
      return;
    }
    if (result.view) {
      setPayload(result);
      if (result.data && "error" in result.data && result.data.error)
        throw new Error(errorText(result.data.error));
      return;
    }
    setModal(null);
    setNotice(t("操作已完成"));
    if (after) after();
    else await refresh();
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
    <Box inert={navigation.state !== "idle"} aria-busy={busy}>
      {content}
    </Box>
  );
  const managed =
    path.startsWith("/dashboard") ||
    payload?.view === "SecurityView" ||
    (path.startsWith("/account") && !path.endsWith("/login"));
  return (
    <>
      {showProgress && <InitialLoading />}
      {managed ? (
        <Layout
          layout={layout}
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
          key={modal.kind + modal.title}
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
