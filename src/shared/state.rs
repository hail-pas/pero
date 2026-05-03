use crate::config::AppConfig;
use crate::infra::cache::Pool;
use crate::infra::jwt::JwtKeys;
use sqlx::postgres::PgPool;
use std::sync::{Arc, OnceLock};

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cache: Pool,
    pub config: Arc<AppConfig>,
    pub jwt_keys: Arc<JwtKeys>,
    pub discovery_doc: Arc<OnceLock<serde_json::Value>>,
    pub jwks_doc: Arc<OnceLock<serde_json::Value>>,
}

impl AppState {
    pub fn abac_state(&self) -> crate::domain::abac::state::AbacState {
        crate::domain::abac::state::AbacState {
            db: self.db.clone(),
            cache: self.cache.clone(),
            config: Arc::new(self.config.abac.clone()),
        }
    }

    pub fn identity_state(&self) -> crate::domain::identity::state::IdentityState {
        crate::domain::identity::state::IdentityState {
            db: self.db.clone(),
            cache: self.cache.clone(),
            jwt_config: Arc::new(self.config.jwt.clone()),
        }
    }

    pub fn oauth2_state(&self) -> crate::domain::oauth2::state::OAuth2State {
        crate::domain::oauth2::state::OAuth2State {
            db: self.db.clone(),
            cache: self.cache.clone(),
            jwt_keys: self.jwt_keys.clone(),
            config: Arc::new(self.config.oauth2.clone()),
        }
    }

    pub fn social_state(&self) -> crate::domain::social::state::SocialState {
        crate::domain::social::state::SocialState {
            db: self.db.clone(),
            cache: self.cache.clone(),
            oidc_issuer: self.config.oidc.issuer.clone(),
        }
    }

    pub fn sso_state(&self) -> crate::domain::sso::state::SsoState {
        crate::domain::sso::state::SsoState {
            db: self.db.clone(),
            cache: self.cache.clone(),
            jwt_keys: self.jwt_keys.clone(),
            config: Arc::new(self.config.sso.clone()),
        }
    }
}
