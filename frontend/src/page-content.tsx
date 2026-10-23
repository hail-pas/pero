import { Alert } from "@mui/material";
import { useLocation, useNavigate } from "react-router-dom";
import type { ViewEnvelope } from "./contracts";
import { Security } from "./security";
import { Profile } from "./account";
import { Auth } from "./auth";
import { FieldsForm } from "./forms";
import { AdminHome, Home } from "./home";
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
    case "SessionListView":
    case "ActivityListView":
    case "AuthorizationListView":
    case "IdentityListView":
    case "AuditListView":
      return <Security page={page} {...actions} />;
    case "HomeView":
      return <Home />;
    case "AdminHomeView":
      return <AdminHome data={data} />;
    case "LoginView":
    case "AccountLoginView":
    case "RegisterView":
    case "ForgotPasswordView":
    case "ResetPasswordView":
    case "ConsentView":
    case "SocialLinkView":
    case "ConfirmLogoutView":
    case "EndSessionView":
    case "ErrorView":
    case "ForbiddenView":
    case "AdminLoginView":
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
                },
              ]}
              submit={async (values) => {
                if (values.new_password !== values.confirm_password)
                  throw new Error(t("两次输入的密码不一致"));
                await mutate(path, values, () => follow("/account/login"));
              }}
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
