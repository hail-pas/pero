use utoipa::Modify;
use utoipa::OpenApi;
use utoipa::openapi::Server;
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};

use crate::config::DocsConfig;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            );
            components.add_security_scheme(
                "basic_auth",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Basic)),
            );
        }
    }
}

struct ServersAddon {
    servers: Vec<crate::config::DocsServer>,
}

impl Modify for ServersAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if !self.servers.is_empty() {
            openapi.servers = Some(
                self.servers
                    .iter()
                    .map(|s| {
                        Server::builder()
                            .url(&s.url)
                            .description(Some(&s.description))
                            .build()
                    })
                    .collect(),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Pero User Center API",
        version = "0.1.0",
        description = "Unified User Center with OAuth2, OIDC, and ABAC policy engine"
    ),
    modifiers(&SecurityAddon),
    paths(
        crate::api::health::health,
        crate::handler::identity::registration::register,
        crate::handler::identity::registration::create_user,
        crate::handler::identity::login::login,
        crate::handler::identity::login::refresh,
        crate::handler::identity::login::logout,
        crate::handler::identity::profile::get_me,
        crate::handler::identity::profile::update_me,
        crate::handler::identity::profile::list_users,
        crate::handler::identity::profile::get_user,
        crate::handler::identity::profile::update_user,
        crate::handler::identity::profile::delete_user,
        crate::handler::identity::password::change_password,
        crate::handler::identity::binding::list_identities,
        crate::handler::identity::binding::bind,
        crate::handler::identity::binding::unbind,
        crate::handler::identity::user_attrs::list_attributes,
        crate::handler::identity::user_attrs::set_attributes,
        crate::handler::sso::verification::send_verify_email_post,
        crate::handler::sso::verification::send_verify_phone_post,
        crate::handler::app::crud::create_app,
        crate::handler::app::crud::list_apps,
        crate::handler::app::crud::get_app,
        crate::handler::app::crud::update_app,
        crate::handler::app::crud::delete_app,
        crate::handler::oauth2::token::token,
        crate::handler::oauth2::revoke::revoke,
        crate::handler::oauth2::client_management::create_client,
        crate::handler::oauth2::client_management::list_clients,
        crate::handler::oauth2::client_management::get_client,
        crate::handler::oauth2::client_management::update_client,
        crate::handler::oauth2::client_management::delete_client,
        crate::handler::oidc::discovery::discovery,
        crate::handler::oidc::jwks::jwks,
        crate::handler::oidc::userinfo::userinfo,
        crate::handler::abac::evaluate::evaluate,
        crate::handler::abac::policies::create_policy,
        crate::handler::abac::policies::list_policies,
        crate::handler::abac::policies::get_policy,
        crate::handler::abac::policies::update_policy,
        crate::handler::abac::policies::delete_policy,
        crate::handler::abac::policies::assign_policy,
        crate::handler::abac::policies::unassign_policy,
        crate::handler::abac::policies::list_user_policies,
        crate::handler::abac::client_policies::create_policy,
        crate::handler::abac::client_policies::list_policies,
        crate::handler::abac::client_policies::get_policy,
        crate::handler::abac::client_policies::update_policy,
        crate::handler::abac::client_policies::delete_policy,
        crate::handler::abac::client_policies::assign_policy,
        crate::handler::abac::client_policies::unassign_policy,
        crate::handler::abac::client_policies::list_user_policies,
        crate::handler::social::public::list_enabled_providers,
        crate::handler::social::management::create_provider,
        crate::handler::social::management::list_providers,
        crate::handler::social::management::get_provider,
        crate::handler::social::management::update_provider,
        crate::handler::social::management::delete_provider,
    ),
    components(
        schemas(
            crate::api::health::HealthStatus,
            crate::domain::identity::models::UserDTO,
            crate::domain::identity::models::RegisterRequest,
            crate::domain::identity::models::CreateUserRequest,
            crate::domain::identity::models::UpdateUserRequest,
            crate::domain::identity::models::UpdateMeRequest,
            crate::domain::identity::models::LoginRequest,
            crate::domain::identity::models::TokenResponse,
            crate::domain::identity::models::RefreshRequest,
            crate::domain::identity::models::BindRequest,
            crate::domain::identity::models::ChangePasswordRequest,
            crate::domain::identity::entity::Identity,
            crate::domain::identity::store::UserAttribute,
            crate::domain::identity::store::SetAttributes,
            crate::domain::app::models::AppDTO,
            crate::domain::app::models::CreateAppRequest,
            crate::domain::app::models::UpdateAppRequest,
            crate::domain::oauth2::models::OAuth2ClientDTO,
            crate::domain::oauth2::models::CreateClientRequest,
            crate::domain::oauth2::models::CreateClientResponse,
            crate::domain::oauth2::models::UpdateClientRequest,
            crate::domain::oauth2::models::TokenRequest,
            crate::domain::oauth2::models::TokenResponse,
            crate::domain::oauth2::models::RevokeRequest,
            crate::domain::oauth2::models::AuthorizeQuery,
            crate::domain::abac::models::Policy,
            crate::domain::abac::models::PolicyCondition,
            crate::domain::abac::models::EvaluateRequest,
            crate::domain::abac::models::EvaluateResponse,
            crate::domain::abac::service::PolicyDTO,
            crate::domain::abac::models::CreatePolicyRequest,
            crate::domain::abac::models::UpdatePolicyRequest,
            crate::domain::abac::models::CreateConditionRequest,
            crate::domain::social::entity::SocialProviderPublic,
            crate::domain::social::entity::SocialProviderDTO,
            crate::domain::social::entity::CreateSocialProviderRequest,
            crate::domain::social::entity::UpdateSocialProviderRequest,
        )
    ),
    tags(
        (name = "Health", description = "Health check"),
        (name = "Identity", description = "User registration, login, profile, password, binding"),
        (name = "Apps", description = "Application management"),
        (name = "OAuth2", description = "OAuth2 authorization, token, client management"),
        (name = "OIDC", description = "OpenID Connect discovery, JWKS, UserInfo"),
        (name = "ABAC", description = "Policy management and user-policy assignment"),
        (name = "Client ABAC", description = "Client-scoped policy management"),
        (name = "Social", description = "Social login provider management"),
    )
)]
struct ApiDoc;

pub fn build_openapi(cfg: &DocsConfig) -> utoipa::openapi::OpenApi {
    let mut spec = ApiDoc::openapi();
    ServersAddon {
        servers: cfg.servers.clone(),
    }
    .modify(&mut spec);
    spec
}
