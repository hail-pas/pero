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
        crate::routes::health::health,
        crate::domains::identity::routes::registration::register,
        crate::domains::identity::routes::registration::create_user,
        crate::domains::identity::routes::login::login,
        crate::domains::identity::routes::login::refresh,
        crate::domains::identity::routes::login::logout,
        crate::domains::identity::routes::profile::get_me,
        crate::domains::identity::routes::profile::update_me,
        crate::domains::identity::routes::profile::list_users,
        crate::domains::identity::routes::profile::get_user,
        crate::domains::identity::routes::profile::update_user,
        crate::domains::identity::routes::profile::delete_user,
        crate::domains::identity::routes::password::change_password,
        crate::domains::identity::routes::binding::bind,
        crate::domains::identity::routes::binding::unbind,
        crate::domains::identity::routes::user_attrs::list_attributes,
        crate::domains::identity::routes::user_attrs::set_attributes,
        crate::domains::app::routes::crud::create_app,
        crate::domains::app::routes::crud::list_apps,
        crate::domains::app::routes::crud::get_app,
        crate::domains::app::routes::crud::update_app,
        crate::domains::app::routes::crud::delete_app,
        crate::domains::oauth2::routes::token::token,
        crate::domains::oauth2::routes::revoke::revoke,
        crate::domains::oauth2::routes::client_management::create_client,
        crate::domains::oauth2::routes::client_management::list_clients,
        crate::domains::oauth2::routes::client_management::get_client,
        crate::domains::oauth2::routes::client_management::update_client,
        crate::domains::oauth2::routes::client_management::delete_client,
        crate::domains::oidc::routes::discovery::discovery,
        crate::domains::oidc::routes::jwks::jwks,
        crate::domains::oidc::routes::userinfo::userinfo,
        crate::domains::abac::routes::policies::create_policy,
        crate::domains::abac::routes::policies::list_policies,
        crate::domains::abac::routes::policies::get_policy,
        crate::domains::abac::routes::policies::update_policy,
        crate::domains::abac::routes::policies::delete_policy,
        crate::domains::abac::routes::policies::assign_policy,
        crate::domains::abac::routes::policies::unassign_policy,
        crate::domains::abac::routes::policies::list_user_policies,
    ),
    components(
        schemas(
            crate::routes::health::HealthStatus,
            crate::domains::identity::models::UserDTO,
            crate::domains::identity::models::RegisterRequest,
            crate::domains::identity::models::CreateUserRequest,
            crate::domains::identity::models::UpdateUserRequest,
            crate::domains::identity::models::UpdateMeRequest,
            crate::domains::identity::models::LoginRequest,
            crate::domains::identity::models::TokenResponse,
            crate::domains::identity::models::RefreshRequest,
            crate::domains::identity::models::BindRequest,
            crate::domains::identity::models::ChangePasswordRequest,
            crate::domains::identity::repos::user_attr::UserAttribute,
            crate::domains::identity::repos::user_attr::SetAttributes,
            crate::domains::app::models::AppDTO,
            crate::domains::app::models::CreateAppRequest,
            crate::domains::app::models::UpdateAppRequest,
            crate::domains::oauth2::models::OAuth2ClientDTO,
            crate::domains::oauth2::models::CreateClientRequest,
            crate::domains::oauth2::models::UpdateClientRequest,
            crate::domains::oauth2::models::TokenRequest,
            crate::domains::oauth2::models::TokenResponse,
            crate::domains::oauth2::models::RevokeRequest,
            crate::domains::oauth2::models::AuthorizeQuery,
            crate::domains::abac::models::Policy,
            crate::domains::abac::models::PolicyCondition,
            crate::domains::abac::routes::policies::PolicyDTO,
            crate::domains::abac::models::CreatePolicyRequest,
            crate::domains::abac::models::UpdatePolicyRequest,
            crate::domains::abac::models::CreateConditionRequest,
        )
    ),
    tags(
        (name = "Health", description = "Health check"),
        (name = "Identity", description = "User registration, login, profile, password, binding"),
        (name = "Apps", description = "Application management"),
        (name = "OAuth2", description = "OAuth2 authorization, token, client management"),
        (name = "OIDC", description = "OpenID Connect discovery, JWKS, UserInfo"),
        (name = "ABAC", description = "Policy management and user-policy assignment"),
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
