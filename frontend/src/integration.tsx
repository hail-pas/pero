import {
  Alert,
  Box,
  Button,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useState } from "react";
import {
  Link as RouterLink,
  useRevalidator,
  useSearchParams,
} from "react-router-dom";
import type { ViewDataMap } from "./contracts";
import { FieldsForm, clientFields } from "./forms";
import { Heading, Panel, type Actions } from "./shared";
import { errorText } from "./api";
import { t, useLocale } from "./i18n";

function checkText(code: string) {
  const messages: Record<string, string> = {
    app_active: t("应用已启用"),
    signing_key: t("存在有效签名密钥"),
    client_active: t("客户端已启用"),
    openid: t("允许 openid 范围"),
    code_grant: t("允许授权码流程"),
    pkce: t("已要求 PKCE（S256）"),
    redirects: t("回调地址格式有效"),
    membership: t("当前测试账号拥有此应用访问资格"),
    test_callback: t("已登记诊断回调地址"),
  };
  return messages[code] || code;
}
export function Integration({
  data: d,
  editor,
  mutate,
}: { data: ViewDataMap["IntegrationView"] } & Actions) {
  useLocale();
  const [params, setParams] = useSearchParams();
  const revalidator = useRevalidator();
  const [type, setType] = useState("confidential");
  const c = d.clients.find((c) => c.id === d.selected_client);
  const base = `/dashboard/apps/${d.app.id}/integration`;
  const issuer = d.issuer.replace(/\/$/, "");
  const configuration = c
    ? {
        issuer: d.issuer,
        discovery_url: `${issuer}/.well-known/openid-configuration`,
        client_id: c.identifier,
        token_endpoint_auth_method:
          c.type === "public" ? "none" : "client_secret_basic",
        redirect_uris: c.redirect_uris.filter((u) => u !== d.callback_uri),
        scope: c.scopes.join(" "),
        response_type: "code",
        code_challenge_method: "S256",
      }
    : null;
  return (
    <>
      <Heading
        title={t("接入向导与诊断")}
        description={d.app.name}
        back={`/dashboard/apps/${d.app.id}`}
      />
      {d.error === "integration_test_expired" && (
        <Button component={RouterLink} to={base} sx={{ mb: 2 }}>
          {t("重新开始诊断")}
        </Button>
      )}
      {d.error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {errorText(d.error)}
        </Alert>
      )}
      {d.test_success && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {t(
            "诊断成功：授权回调、state、PKCE、令牌兑换、ID Token 签名与 nonce、访问令牌在线状态均已通过。",
          )}
        </Alert>
      )}
      <Panel title={t("1. 选择客户端类型并创建")}>
        <Stack spacing={2}>
          <TextField
            select
            label={t("应用运行方式")}
            value={type}
            onChange={(e) => setType(e.target.value)}
          >
            <MenuItem value="confidential">
              {t("服务端 Web 应用（可保管密钥）")}
            </MenuItem>
            <MenuItem value="public">{t("浏览器 SPA（不保管密钥）")}</MenuItem>
          </TextField>
          <Typography variant="body2">
            {t(
              "两种类型均使用授权码和 PKCE。密钥只存放在业务服务端；SPA 不使用客户端密钥。",
            )}
          </Typography>
          <Typography variant="body2">
            {t(
              "创建时填写业务回调地址；需要运行本站诊断时，额外保留下方诊断回调地址。",
            )}
          </Typography>
          <Button
            onClick={() =>
              editor(
                t("新建 OAuth 客户端"),
                "/dashboard/clients/new",
                clientFields,
                {
                  client_type: type,
                  require_pkce: true,
                  scopes: "openid,profile,email",
                  grant_types: "authorization_code,refresh_token",
                  redirect_uris: d.callback_uri,
                },
                { app_id: d.app.id },
              )
            }
          >
            {t("使用推荐配置创建客户端")}
          </Button>
          <Button
            disabled={revalidator.state !== "idle"}
            onClick={() => revalidator.revalidate()}
          >
            {t("刷新客户端列表")}
          </Button>
        </Stack>
      </Panel>
      <Panel title={t("2. 获取接入配置与检查结果")}>
        <Stack spacing={2}>
          {d.clients.length > 0 ? (
            <TextField
              select
              label={t("OAuth 客户端")}
              value={c?.id || ""}
              onChange={(e) => {
                const next = new URLSearchParams(params);
                next.set("client", e.target.value);
                next.delete("test");
                next.delete("test_error");
                setParams(next);
              }}
            >
              {d.clients.map((c) => (
                <MenuItem key={c.id} value={c.id}>
                  {c.name || c.identifier}
                </MenuItem>
              ))}
            </TextField>
          ) : (
            <Typography>{t("请先创建客户端。")}</Typography>
          )}
          {configuration && (
            <Box
              component="pre"
              sx={{
                overflowX: "auto",
                whiteSpace: "pre-wrap",
                overflowWrap: "anywhere",
                userSelect: "all",
              }}
            >
              {JSON.stringify(configuration, null, 2)}
            </Box>
          )}
          {d.checks.map((check) => (
            <Alert
              key={check.code}
              severity={check.passed ? "success" : "warning"}
            >
              {checkText(check.code)}
            </Alert>
          ))}
          <Typography variant="body2">
            {t(
              "回调必须与登记地址完全一致。state、nonce 和 PKCE verifier 应由接入应用逐次生成并绑定本次登录。",
            )}
          </Typography>
          <Typography variant="body2">
            {t(
              "缺少访问资格时，请先在应用成员页面授予测试账号资格；授权不会自动添加成员。",
            )}
          </Typography>
          <Button component={RouterLink} to={`/dashboard/apps/${d.app.id}`}>
            {t("返回应用修改配置")}
          </Button>
        </Stack>
      </Panel>
      {c && (
        <Panel title={t("3. 运行授权与令牌诊断")}>
          <Stack spacing={2}>
            <Alert severity="info">
              {t(
                "这是认证中心内部诊断。通过后仍需在业务应用验证真实回调、Cookie 和退出流程；不能替代业务应用验收。",
              )}
            </Alert>
            <Typography>
              {t(
                "请将此地址额外登记到所选客户端的回调列表，诊断完成后可移除：",
              )}
            </Typography>
            <Box
              component="code"
              sx={{ overflowWrap: "anywhere", userSelect: "all" }}
            >
              {d.callback_uri}
            </Box>
            {!d.test_ready ? (
              <FieldsForm
                fields={[]}
                label={t("开始测试登录")}
                submit={() =>
                  mutate(base, { action: "start", client_id: c.id })
                }
              />
            ) : (
              <>
                <Alert severity="success">
                  {t(
                    "授权回调已收到。继续兑换令牌并验证签名；客户端密钥不会保存。",
                  )}
                </Alert>
                <FieldsForm
                  fields={
                    c.type === "public"
                      ? []
                      : [
                          {
                            name: "client_secret",
                            label: t("客户端密钥"),
                            type: "password",
                            required: true,
                          },
                        ]
                  }
                  label={t("兑换并验证令牌")}
                  submit={(v) =>
                    mutate(base, {
                      ...v,
                      action: "finish",
                      client_id: c.id,
                      test: d.test,
                    })
                  }
                />
              </>
            )}
            <Typography variant="caption">
              {t(
                "诊断有效期为 10 分钟，绑定当前账号和会话。不会显示令牌，测试产生的刷新令牌立即撤销。",
              )}
            </Typography>
          </Stack>
        </Panel>
      )}
      <Panel title={t("接入排查清单")}>
        <Stack spacing={1}>
          <Typography>
            {t("invalid_redirect_uri：检查协议、域名、端口、路径和末尾斜杠。")}
          </Typography>
          <Typography>
            {t(
              "invalid_client：核对客户端类型、密钥和认证方式，不要同时发送 Basic 和表单密钥。",
            )}
          </Typography>
          <Typography>
            {t(
              "invalid_grant：重新发起授权；授权码只能使用一次，并须匹配原回调和 PKCE verifier。",
            )}
          </Typography>
          <Typography>
            {t(
              "invalid_scope / access_denied：检查允许范围、应用成员资格和应用启用状态。",
            )}
          </Typography>
          <Typography>
            {t(
              "业务服务每次受保护请求应在线校验令牌；503 保留会话并提示稍后重试，失效令牌才清除登录态。",
            )}
          </Typography>
        </Stack>
      </Panel>
    </>
  );
}
