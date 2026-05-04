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
        crate::handler::identity::binding::unbind,
        crate::handler::identity::user_attrs::list_attributes,
        crate::handler::identity::user_attrs::set_attributes,
        crate::handler::identity::user_attrs::delete_attribute,
        crate::handler::identity::registration::create_user,
        crate::handler::app::crud::create_app,
        crate::handler::app::crud::list_apps,
        crate::handler::app::crud::get_app,
        crate::handler::app::crud::update_app,
        crate::handler::app::crud::delete_app,
        crate::handler::oauth2::client_management::create_client,
        crate::handler::oauth2::client_management::list_clients,
        crate::handler::oauth2::client_management::get_client,
        crate::handler::oauth2::client_management::update_client,
        crate::handler::oauth2::client_management::delete_client,
        crate::handler::abac::policies::create_policy,
        crate::handler::abac::policies::list_policies,
        crate::handler::abac::policies::get_policy,
        crate::handler::abac::policies::update_policy,
        crate::handler::abac::policies::delete_policy,
        crate::handler::abac::policies::assign_policy,
        crate::handler::abac::policies::unassign_policy,
        crate::handler::abac::policies::list_user_policies,
        crate::handler::abac::evaluate::evaluate,
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
    components(schemas(
        crate::api::health::HealthStatus,
        crate::api::response::MessageResponse,
        crate::api::schemas::user::UserDTO,
        crate::api::schemas::user::RegisterRequest,
        crate::api::schemas::user::TokenResponse,
        crate::api::schemas::user::RefreshTokenResponse,
        crate::api::schemas::user::LoginRequest,
        crate::api::schemas::user::RefreshRequest,
        crate::api::schemas::user::ChangePasswordRequest,
        crate::api::schemas::user::IdentityDTO,
        crate::api::schemas::user::UserAttributeDTO,
        crate::api::schemas::user::UpdateMeRequest,
        crate::api::schemas::user::UpdateUserRequest,
        crate::api::schemas::app::AppDTO,
        crate::api::schemas::app::CreateAppRequest,
        crate::api::schemas::app::UpdateAppRequest,
        crate::api::schemas::oauth::OAuth2ClientDTO,
        crate::api::schemas::oauth::CreateClientResponse,
        crate::api::schemas::oauth::CreateClientRequest,
        crate::api::schemas::oauth::UpdateClientRequest,
        crate::api::schemas::oauth::OAuth2TokenResponse,
        crate::api::schemas::oauth::TokenRequest,
        crate::api::schemas::oauth::RevokeRequest,
        crate::api::schemas::oauth::AuthorizeQuery,
        crate::api::schemas::abac::PolicyDTO,
        crate::api::schemas::abac::PolicyConditionDTO,
        crate::api::schemas::abac::CreatePolicyRequest,
        crate::api::schemas::abac::UpdatePolicyRequest,
        crate::api::schemas::abac::CreateConditionRequest,
        crate::api::schemas::abac::EvaluateRequest,
        crate::api::schemas::abac::EvaluateResponse,
        crate::api::schemas::social::SocialProviderPublicDTO,
        crate::api::schemas::social::SocialProviderDTO,
        crate::api::schemas::social::CreateSocialProviderRequest,
        crate::api::schemas::social::UpdateSocialProviderRequest,
    )),
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
