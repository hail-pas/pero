import type { UserLayout } from "./contracts";
export function can(
  layout: UserLayout | undefined,
  permission: string,
  appId?: string,
) {
  const a = layout?.admin_access;
  return (
    !!a &&
    (a.super_admin ||
      (appId
        ? a.app_grants[appId]?.includes(permission)
        : a.global_permissions.includes(permission)))
  );
}
export const isSuper = (layout: UserLayout | undefined) =>
  !!layout?.admin_access?.super_admin;
