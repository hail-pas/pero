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
  };
  return policy[code] || t("操作未完成（{{0}}）", { "0": code });
}

export async function request(
  path: string,
  values?: Values,
  signal?: AbortSignal,
): Promise<Envelope> {
  const body =
    values &&
    new URLSearchParams(
      Object.entries(values)
        .filter(([, v]) => v != null)
        .map(([k, v]) => [k, String(v)]),
    );
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { Accept: "application/json", "Accept-Language": getLocale() },
    method: body ? "POST" : "GET",
    body,
    signal,
  });
  const statusError =
    response.status === 503 ? "service_unavailable" : String(response.status);
  if (!response.headers.get("content-type")?.includes("application/json"))
    throw new Error(errorText(response.ok ? "invalid_response" : statusError));
  const result: Envelope = await response.json();
  if (!result || typeof result !== "object" || Array.isArray(result))
    throw new Error(errorText("invalid_response"));
  if (!result.view && result.error) throw new Error(errorText(result.error));
  if (!response.ok && !result.view) throw new Error(errorText(statusError));
  if (!result.view && !result.redirect && result.code !== 0)
    throw new Error(errorText("invalid_response"));
  return result;
}
export const lower = (value: unknown) => String(value ?? "").toLowerCase();
export const date = (value?: string | null) =>
  value ? new Date(value).toLocaleString("sv-SE") : "—";
