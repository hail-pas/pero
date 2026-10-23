import { RefreshRounded } from "@mui/icons-material";
import {
  Alert,
  Button,
  Card,
  CardContent,
  Skeleton,
  Stack,
} from "@mui/material";
import { useCallback, useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { errorText, request, type ViewEnvelope, type Values } from "./api";
import type { Field } from "./forms";
import { ActionDialog, type ActionModal } from "./action-dialog";
import { t, useLocale } from "./i18n";
import { Layout } from "./layout";
import { PageContent } from "./page-content";

export function App() {
  const location = useLocation();
  return <Page key={location.pathname + location.search} />;
}

function Page() {
  const { locale } = useLocale();
  const location = useLocation(),
    navigate = useNavigate();
  const [payload, setPayload] = useState<ViewEnvelope>(),
    [loading, setLoading] = useState(true),
    [failure, setFailure] = useState(""),
    [notice, setNotice] = useState(""),
    [modal, setModal] = useState<ActionModal | null>(null),
    [revision, setRevision] = useState(0);
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
      if (
        url.origin !== window.location.origin ||
        url.pathname.startsWith("/oauth2") ||
        (url.pathname.includes("/social/") && !url.pathname.endsWith("/link"))
      )
        window.location.assign(url.href);
      else navigate(url.pathname + url.search, { replace: true });
    },
    [navigate],
  );
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setFailure("");
    request(path + location.search, undefined, controller.signal)
      .then((result) => {
        if (!result.view && result.redirect) follow(result.redirect);
        else if (result.view) setPayload(result);
        else throw new Error(errorText("invalid_response"));
      })
      .catch((e) => {
        if (e.name !== "AbortError") setFailure(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [path, location.search, revision, follow]);
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
    const result = await request(endpoint, {
      ...values,
      csrf_token: csrfToken,
    });
    if (!result.view && result.redirect) {
      follow(result.redirect);
      return;
    }
    if (result.data && "secret" in result.data && result.data.secret) {
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
    else setRevision((n) => n + 1);
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
  if (loading)
    content = (
      <Stack spacing={3}>
        <Skeleton width="35%" height={50} />
        <Skeleton variant="rounded" height={150} />
        <Skeleton variant="rounded" height={300} />
      </Stack>
    );
  else if (failure)
    content = (
      <Card>
        <CardContent>
          <Alert severity="error">{t(failure)}</Alert>
          <Button
            sx={{ mt: 2 }}
            onClick={() => setRevision((n) => n + 1)}
            startIcon={<RefreshRounded />}
          >
            {t("重新加载")}
          </Button>
        </CardContent>
      </Card>
    );
  else if (payload)
    content = <PageContent page={payload} actions={actions} follow={follow} />;
  const managed =
    path.startsWith("/dashboard") ||
    (path.startsWith("/account") && !path.endsWith("/login"));
  return (
    <>
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
          {notice && (
            <Alert sx={{ mb: 3 }} onClose={() => setNotice("")}>
              {t(notice)}
            </Alert>
          )}
          {content}
        </Layout>
      ) : (
        <>{content}</>
      )}
      {modal && (
        <ActionDialog
          key={modal.kind + modal.title}
          modal={modal}
          mutate={mutate}
          onClose={() => {
            setModal(null);
            if (modal.kind === "secret") setRevision((n) => n + 1);
          }}
        />
      )}
    </>
  );
}
