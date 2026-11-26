import {
  Enrollment,
  EnrollmentAdmin,
  Admission,
  AppMembers,
} from "./enrollment";
import { UserSecurity } from "./user-security";
import { Tenants } from "./tenants";
import { Integration } from "./integration";
import { Notifications } from "./notifications";
import { SecurityCenter, AdminRoles } from "./security-center";
import { Alert, Button, Stack } from "@mui/material";
import {
  Link as RouterLink,
  useLocation,
  useNavigate,
} from "react-router-dom";
import type { ViewEnvelope } from "./contracts";
import { Security, AuditDetail } from "./security";
import { Profile } from "./account";
import { Auth } from "./auth";
import { FieldsForm } from "./forms";
import { Home } from "./home";
import { ManagementForm } from "./management-form";
import { ManagementList } from "./management";
import { ManagementDetail } from "./management-detail";
import { Heading, Panel, type Actions } from "./shared";
import { t, useLocale } from "./i18n";

export function PageContent({
  page,
  actions,
  follow,
}: {
  page: ViewEnvelope;
  actions: Actions;
  follow: (target: string) => void;
}) {
  useLocale();
  const { pathname: path } = useLocation();
  const navigate = useNavigate();
  const { mutate } = actions;
  const { view, data } = page;
  switch (view) {
    case "TenantAdminView":
    case "TenantAdminDetailView":
    case "TenantListView":
    case "TenantDetailView":
    case "TenantChoiceView":
      return <Tenants page={page} {...actions} />;
    case "UserSecurityView":
      return <UserSecurity data={data} {...actions} />;
    case "IntegrationView":
      return <Integration data={data} {...actions} />;
    case "EnrollmentView":
      return <Enrollment data={data} mutate={mutate} />;
    case "EnrollmentAdminView":
      return <EnrollmentAdmin data={data} {...actions} />;
    case "AppMembersView":
      return <AppMembers data={data} {...actions} />;
    case "AdmissionView":
      return <Admission data={data} {...actions} />;
    case "NotificationListView":
      return <Notifications data={data} {...actions} />;
    case "SecurityView":
      return <SecurityCenter data={data} mutate={mutate} />;
    case "DashboardEmptyView":
      return (
        <>
          <Heading
            title={t("管理控制台")}
            description={t("管理工作空间中的用户、应用与安全策略。")}
          />
          <Panel title={t("访问权限")}>
            <Stack spacing={2} sx={{ alignItems: "flex-start" }}>
              <Alert severity="info" sx={{ width: "100%" }}>
                {t("尚未分配权限，可返回个人中心。")}
              </Alert>
              <Button
                component={RouterLink}
                to="/account/profile"
                variant="contained"
              >
                {t("返回个人中心")}
              </Button>
            </Stack>
          </Panel>
        </>
      );
    case "AdminRolesView":
      return <AdminRoles data={data} mutate={mutate} ask={actions.ask} />;
    case "AuditDetailView":
      return <AuditDetail data={data} />;
    case "SessionListView":
    case "ActivityListView":
    case "AuthorizationListView":
    case "IdentityListView":
    case "AuditListView":
      return <Security page={page} {...actions} />;
    case "HomeView":
      return <Home data={data} />;
    case "AppAccessDeniedView":
    case "SelectAccountView":
    case "LoginView":
    case "AccountLoginView":
    case "ForgotPasswordView":
    case "ResetPasswordView":
    case "ConsentView":
    case "SocialLinkView":
    case "ConfirmLogoutView":
    case "EndSessionView":
    case "ErrorView":
    case "ForbiddenView":
      return <Auth page={page} mutate={mutate} />;
    case "ProfileView":
      return <Profile data={data} {...actions} />;
    case "ChangePasswordView":
      return (
        <>
          <Heading
            title={t("账户安全")}
            description={t("管理登录密码，保护你的账户。")}
          />
          <Panel title={data.has_password ? t("修改密码") : t("设置本地密码")}>
            <Alert severity="info" sx={{ mb: 3 }}>
              {t("保存新密码后，所有登录会话将退出，你需要重新登录。")}
            </Alert>
            <FieldsForm
              fields={[
                ...(data.has_password
                  ? [
                      {
                        name: "old_password",
                        label: t("当前密码"),
                        type: "password",
                        required: true,
                      },
                    ]
                  : []),
                {
                  name: "new_password",
                  label: t("新密码"),
                  type: "password",
                  required: true,
                },
                {
                  name: "confirm_password",
                  label: t("确认新密码"),
                  type: "password",
                  required: true,
                  validate: (value, values) =>
                    value && value !== values.new_password
                      ? t("两次输入的密码不一致")
                      : undefined,
                },
              ]}
              submit={(values) =>
                mutate(path, values, () => follow("/account/login"))
              }
            />
          </Panel>
        </>
      );
    case "VerifyContactView":
      return (
        <>
          <Heading
            title={t("验证联系方式")}
            description={t("验证码已发送至 {{0}}", { "0": data.masked_value })}
          />
          <Panel title={t("输入验证码")}>
            <FieldsForm
              fields={[{ name: "code", label: t("验证码"), required: true }]}
              submit={(values) =>
                mutate(
                  "/account/profile/verify-contact",
                  { ...values, nonce: data.nonce },
                  () => navigate("/account/profile"),
                )
              }
              label={t("确认验证")}
            />
          </Panel>
        </>
      );
    case "AppListView":
    case "UserListView":
    case "ProviderListView":
      return <ManagementList page={page} />;
    case "AppFormView":
    case "UserFormView":
    case "ProviderFormView":
      return <ManagementForm page={page} mutate={mutate} />;
    case "AppDetailView":
    case "UserDetailView":
    case "ProviderDetailView":
      return <ManagementDetail page={page} {...actions} />;
    default:
      page satisfies never;
      return null;
  }
}
