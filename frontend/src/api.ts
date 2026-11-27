import { getLocale, t } from "./i18n";
import messages from "./messages.json";
import type { Envelope, Values } from "./contracts";
export type { Envelope, Values, ViewEnvelope } from "./contracts";
const dictionary: Record<string, string> = messages;
export function errorText(code: string, showDetails = false) {
  if (typeof code !== "string") return t(dictionary.invalid_response);
  const minimum = code.match(/^password must be at least (\d+) characters$/);
  const maximum = code.match(/^password must be at most (\d+) characters$/);
  if (minimum) return t("密码长度至少 {{0}} 个字符", { "0": minimum[1] });
  if (maximum) return t("密码长度不能超过 {{0}} 个字符", { "0": maximum[1] });
  if (Object.hasOwn(dictionary, code)) return t(dictionary[code]);
  const fallbacks: Record<string, string> = {
    "password must contain an uppercase letter": t("密码需包含大写字母"),
    "password must contain a lowercase letter": t("密码需包含小写字母"),
    "password must contain a digit": t("密码需包含数字"),
    "password must contain a special character": t("密码需包含特殊字符"),
    network_error: t("网络连接失败，请检查网络后重试。"),
    "400": t("请求无效，请刷新页面后重试。"),
    "401": t("登录已失效，请重新登录。"),
    "403": t("此操作暂不可用，请检查权限或联系管理员。"),
    "404": t("记录或页面不存在，请刷新后重试。"),
    "405": t("此页面不支持该操作。"),
    "409": t("数据已发生变化，请刷新后重试。"),
    "413": t("提交的内容过大，请缩减后重试。"),
    "415": t("提交的内容格式不受支持。"),
    "422": t("请检查填写的内容后重试。"),
    "429": t("操作过于频繁，请稍后重试。"),
    "500": t("服务暂时不可用，请稍后重试。"),
    "502": t("服务暂时不可用，请稍后重试。"),
    "503": t("服务暂时不可用，请稍后重试。"),
    "504": t("服务暂时不可用，请稍后重试。"),
  };
  return Object.hasOwn(fallbacks, code)
    ? fallbacks[code]
    : showDetails
      ? t("操作未完成（{{0}}）", { "0": code })
      : t("操作未完成，请重试。");
}

export const isEnrollmentPath = (path: string) =>
  /^\/sso\/register(?:\/login)?(?:\?|$)/.test(path);

export class RequestError extends Error {
  constructor(
    readonly code: string,
    readonly status?: number,
  ) {
    super(errorText(code));
  }
}

export function requestErrorText(error: unknown) {
  return error instanceof RequestError
    ? errorText(error.code)
    : t("操作未完成，请重试。");
}

export async function fetchApi(path: string, options: RequestInit = {}) {
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  headers.set("Accept-Language", getLocale());
  return fetch(path, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
    headers,
  }).catch((error: unknown) => {
    if (options.signal?.aborted) throw error;
    throw new RequestError("network_error");
  });
}

function verifyJsonResponse(response: Response) {
  if (!response.headers.get("content-type")?.includes("application/json"))
    throw new RequestError(
      response.ok ? "invalid_response" : String(response.status),
      response.status,
    );
}

export async function readJson(response: Response): Promise<unknown> {
  verifyJsonResponse(response);
  return response.json().catch(() => {
    throw new RequestError("invalid_response", response.status);
  });
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
  const response = await fetchApi(path, {
    headers: permissions ? { "Content-Type": "application/json" } : undefined,
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
  });
  // fetch follows HTTP redirects. Resolve the final URL before rendering its
  // view, otherwise the content and the router location disagree.
  if (response.redirected && response.ok) {
    verifyJsonResponse(response);
    const destination = new URL(response.url);
    const source = new URL(path, window.location.origin);
    if (destination.href !== source.href) return { redirect: destination.href };
  }
  const result = (await readJson(response)) as Envelope;
  if (!result || typeof result !== "object" || Array.isArray(result))
    throw new RequestError("invalid_response", response.status);
  if (!result.view && result.error)
    throw new RequestError(
      typeof result.error === "string" ? result.error : "invalid_response",
      response.status,
    );
  if (!response.ok && !result.view)
    throw new RequestError(String(response.status), response.status);
  if (!result.view && !result.redirect && result.code !== 0)
    throw new RequestError("invalid_response", response.status);
  return result;
}
export const lower = (value: unknown) => String(value ?? "").toLowerCase();
export function date(value?: string | null, includeTime = true) {
  const instant = value ? new Date(value) : undefined;
  if (!instant || Number.isNaN(instant.getTime())) return "—";
  return instant.toLocaleString(getLocale(), {
    dateStyle: "medium",
    ...(includeTime && { timeStyle: "medium" }),
  });
}

export function dateTimeInput(value: string) {
  const instant = new Date(value);
  if (Number.isNaN(instant.getTime())) return "";
  const local = new Date(
    instant.getTime() - instant.getTimezoneOffset() * 60_000,
  );
  return local.toISOString().slice(0, 16);
}
