export type Values = Record<
  string,
  string | boolean | number | null | undefined
>;
export type DateValue = string;
export interface UserLayout {
  user_name: string;
  user_username: string;
  user_avatar_url: string;
  is_admin?: boolean;
}
export interface AppSummary {
  id: string;
  code: string;
  name: string;
  type: string;
  description: string | null;
  homepage_url: string | null;
  logo_url: string | null;
  status: string;
  auto_access: boolean;
  system: boolean;
  created_at: DateValue;
}
export interface UserSummary {
  id: string;
  username: string;
  email: string | null;
  phone: string | null;
  nickname: string | null;
  avatar_url: string | null;
  status: string;
  created_at: DateValue;
}
export interface ProviderSummary {
  id: string;
  code: string;
  name: string;
  kind: string;
  issuer: string | null;
  client_id: string | null;
  enabled: boolean;
  created_at: DateValue;
}
export interface ClientSummary {
  id: string;
  identifier: string;
  name: string | null;
  type: string;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  scopes: string[];
  grant_types: string[];
  require_pkce: boolean;
  access_token_ttl_seconds: number;
  refresh_token_ttl_seconds: number;
  id_token_ttl_seconds: number;
  status: string;
}
export interface KeySummary {
  id: string;
  kid: string;
  algorithm: string;
  active: boolean;
  revoked_at: DateValue | null;
}
export interface ProfileUser {
  username: string;
  nickname: string;
  email: string;
  phone: string;
  avatar_url: string;
  created_at: string;
  email_verified: boolean;
  phone_verified: boolean;
  has_password: boolean;
  pending_email_nonce: string;
  pending_email_value: string;
  pending_phone_nonce: string;
  pending_phone_value: string;
}
interface CsrfPage {
  csrf_token: string;
}
interface AccountPage extends CsrfPage {
  layout: UserLayout;
}
interface LoginPage extends CsrfPage {
  error: string;
  providers: { key: string; name: string; icon: string }[];
}
interface ListPage extends AccountPage {
  page: number;
  total_pages: number;
}
interface FormPage extends AccountPage {
  mode: "create" | "edit";
  form: Values;
  error: string;
}
export interface RowsPage<T> extends ListPage {
  rows: T[];
}
export interface ViewDataMap {
  SecurityView: {
    layout?: UserLayout;
    csrf_token: string;
    enabled: boolean;
    required: boolean;
    pending: boolean;
    recovery: boolean;
    has_password: boolean;
    secret: string;
    qr: string;
    codes: string[];
    redirect: string;
    error: string;
    providers: { key: string; name: string }[];
  };
  AdminRolesView: AccountPage & {
    rows: { user_id: string; username: string; role: string }[];
  };
  SessionListView: RowsPage<{
    id: string;
    ip: string | null;
    user_agent: string | null;
    current: boolean;
    authentication_pending: boolean;
    created_at: string;
    last_seen_at: string;
    expires_at: string;
  }>;
  ActivityListView: RowsPage<{
    id: string;
    user_id: string | null;
    username: string;
    provider_name: string;
    event_type: string;
    ip: string | null;
    user_agent: string | null;
    created_at: string;
  }>;
  AuthorizationListView: RowsPage<{
    client_id: string;
    client_name: string;
    app_id: string;
    app_name: string;
    scopes: string[];
    granted_at: string;
  }>;
  IdentityListView: AccountPage & {
    rows: {
      id: string;
      provider_name: string;
      enabled: boolean;
      last_login_at: string | null;
    }[];
    providers: { key: string; name: string; icon: string }[];
    has_password: boolean;
    error: string;
  };
  AuditListView: RowsPage<{
    id: string;
    actor_id: string;
    actor_username: string;
    action: string;
    target: string;
    outcome: string;
    http_status: number | null;
    ip: string | null;
    request_id: string | null;
    created_at: string;
  }>;
  NotificationListView: RowsPage<{
    id: string;
    kind: string;
    channel: string;
    recipient: string;
    status: string;
    attempts: number;
    last_error: string | null;
    http_status: number | null;
    created_at: string;
    updated_at: string;
    can_retry: boolean;
  }> & {
    enabled: boolean;
    summary: { pending: number; overdue: number; failing: number };
  };
  HomeView: null;
  AdminHomeView: CsrfPage & {
    username: string;
    email: string;
    picture: string;
    profile_url: string;
    password_url: string;
    issuer: string;
  };
  LoginView: LoginPage;
  AccountLoginView: LoginPage & { redirect: string };
  AdminLoginView: { authorize_url: string; error: string };
  RegisterView: CsrfPage & { error: string };
  ForgotPasswordView: CsrfPage & { error: string; success: boolean };
  ResetPasswordView: CsrfPage & {
    token: string;
    error: string;
    success: string;
  };
  ConsentView: CsrfPage & {
    request_token: string;
    client_name: string;
    client_url: string;
    user_name: string;
    user_email: string;
    user_avatar_url: string;
    user_initial: string;
    scopes: string[];
  };
  SocialLinkView: CsrfPage & {
    has_password: boolean;
    nonce: string;
    provider_name: string;
    account_email: string;
    display_name: string;
    error: string;
  };
  ConfirmLogoutView: CsrfPage & {
    session_id: string;
    id_token_hint: string;
    post_logout_redirect_uri: string;
    state: string;
  };
  EndSessionView: null;
  ErrorView: { code: string };
  ForbiddenView: { code: string };
  ProfileView: AccountPage & { user: ProfileUser };
  ChangePasswordView: AccountPage & { has_password: boolean };
  VerifyContactView: AccountPage & {
    nonce: string;
    masked_value: string;
    change_type: string;
  };
  AppListView: ListPage & {
    apps: AppSummary[];
    q: string;
    status_filter: string;
    type_filter: string;
  };
  UserListView: ListPage & {
    users: UserSummary[];
    q: string;
    status_filter: string;
  };
  ProviderListView: ListPage & { providers: ProviderSummary[] };
  AppFormView: FormPage & { app_id: string };
  UserFormView: FormPage & { user_id: string };
  ProviderFormView: FormPage & { provider_id: string };
  AppDetailView: AccountPage & {
    app: AppSummary;
    clients: ClientSummary[];
    error: string;
  };
  UserDetailView: AccountPage & {
    user: UserSummary;
    identities: {
      id: string;
      kind: string;
      provider_name: string;
      provider_code: string;
      last_login_at: string | null;
    }[];
    access_list: {
      app_id: string;
      app_code: string;
      app_name: string;
      status: string;
    }[];
    all_apps: [string, string, string][];
    error: string;
  };
  ProviderDetailView: AccountPage & {
    provider: ProviderSummary;
    keys: KeySummary[];
    error: string;
  };
}
export type ViewName = keyof ViewDataMap;
export type ViewEnvelope<V extends ViewName = ViewName> = {
  [K in V]: { view: K; data: ViewDataMap[K] };
}[V];
export type AuthView =
  | "LoginView"
  | "AccountLoginView"
  | "RegisterView"
  | "ForgotPasswordView"
  | "ResetPasswordView"
  | "ConsentView"
  | "SocialLinkView"
  | "ConfirmLogoutView"
  | "EndSessionView"
  | "ErrorView"
  | "ForbiddenView"
  | "AdminLoginView";
export type ListView = "AppListView" | "UserListView" | "ProviderListView";
export type FormView = "AppFormView" | "UserFormView" | "ProviderFormView";
export type DetailView =
  "AppDetailView" | "UserDetailView" | "ProviderDetailView";
export type ActionResponse = {
  redirect?: string;
  error?: string;
  code?: number;
  data?: { secret?: string; nonce?: string };
  view?: never;
};
export type Envelope = ViewEnvelope | ActionResponse;
