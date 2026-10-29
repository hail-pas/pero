import { getLocale, t } from "./i18n";
import messages from "./messages.json";
import type { Envelope, Values } from "./contracts";
export type { Envelope, Values, ViewEnvelope } from "./contracts";
const dictionary: Record<string, string> = messages;
export function errorText(code: string) {
  const minimum = code.match(/^password must be at least (\d+) characters$/);
  const maximum = code.match(/^password must be at most (\d+) characters$/);
  if (minimum) return t("密码长度至少 {{0}} 个字符", { "0": minimum[1] });
  if (maximum) return t("密码长度不能超过 {{0}} 个字符", { "0": maximum[1] });
  const message = dictionary[code];
  if (message) return t(message);
  const policy: Record<string, string> = {
    "password must contain an uppercase letter": t("密码需包含大写字母"),
    "password must contain a lowercase letter": t("密码需包含小写字母"),
    "password must contain a digit": t("密码需包含数字"),
    "password must contain a special character": t("密码需包含特殊字符"),
    forbidden: t("你没有管理权限。"),
    service_unavailable: t("服务暂时不可用，请稍后重试。"),
    network_error: t("网络连接失败，请检查网络后重试。"),
    "401": t("登录已失效，请重新登录。"),
    "403": t("此操作暂不可用，请检查权限或联系管理员。"),
    "404": t("记录或页面不存在，请刷新后重试。"),
    "409": t("数据已发生变化，请刷新后重试。"),
    "429": t("操作过于频繁，请稍后重试。"),
    "500": t("服务暂时不可用，请稍后重试。"),
    "502": t("服务暂时不可用，请稍后重试。"),
    "503": t("服务暂时不可用，请稍后重试。"),
    "504": t("服务暂时不可用，请稍后重试。"),
  };
  return policy[code] || t("操作未完成（{{0}}）", { "0": code });
}

export async function request(
  path: string,
  values?: Values,
  signal?: AbortSignal,
): Promise<Envelope> {
  const permissions = path.endsWith("/permissions") && values;
  const body =
    values &&
    new URLSearchParams(
      Object.entries(values)
        .filter(([, v]) => v != null)
        .map(([k, v]) => [k, String(v)]),
    );
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "Accept-Language": getLocale(),
      ...(permissions ? { "Content-Type": "application/json" } : {}),
    },
    method: body ? "POST" : "GET",
    body: permissions
      ? JSON.stringify({
          revision: values.revision,
          csrf_token: values.csrf_token,
          global_permissions: JSON.parse(String(values.global_permissions)),
          app_grants: JSON.parse(String(values.app_grants)),
        })
      : body,
    signal,
    cache: "no-store",
  }).catch((error: unknown) => {
    if (signal?.aborted) throw error;
    throw new Error(errorText("network_error"));
  });
  const statusError =
    response.status === 503 ? "service_unavailable" : String(response.status);
  if (!response.headers.get("content-type")?.includes("application/json"))
    throw new Error(errorText(response.ok ? "invalid_response" : statusError));
  // fetch follows HTTP redirects. Resolve the final URL before rendering its
  // view, otherwise the content and the router location disagree.
  if (response.redirected && response.ok) {
    const destination = new URL(response.url);
    const source = new URL(path, window.location.origin);
    if (destination.href !== source.href) return { redirect: destination.href };
  }
  const result: Envelope = await response.json().catch(() => {
    throw new Error(errorText("invalid_response"));
  });
  if (!result || typeof result !== "object" || Array.isArray(result))
    throw new Error(errorText("invalid_response"));
  if (!result.view && result.error)
    throw Object.assign(new Error(errorText(result.error)), {
      status: response.status,
      code: result.error,
    });
  if (!response.ok && !result.view) throw new Error(errorText(statusError));
  if (!result.view && !result.redirect && result.code !== 0)
    throw new Error(errorText("invalid_response"));
  return result;
}
export const lower = (value: unknown) => String(value ?? "").toLowerCase();
export const date = (value?: string | null) =>
  value ? new Date(value).toLocaleString("sv-SE") : "—";
