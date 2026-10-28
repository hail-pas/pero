pub mod access;
pub mod account;
pub mod account_security;
pub mod admin;
pub mod app;
pub mod client;
pub mod contact;
pub mod enrollment;
pub mod keys;
pub mod login;
pub mod logout;
pub mod mfa;
pub mod notify;
pub mod oauth;
pub mod password;
pub mod provider;
pub mod recovery;
pub mod scope;
pub mod security;
pub mod session;
pub mod social;
pub mod token;
pub mod user;
pub mod verification;

#[derive(Debug, thiserror::Error)]
pub enum ManagementError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Validation(String),
    #[error("Management dependency unavailable")]
    Dependency(sea_orm::DbErr),
    #[error("Credential processing unavailable")]
    Credential(#[from] pero_error::AppError),
}

impl From<sea_orm::DbErr> for ManagementError {
    fn from(error: sea_orm::DbErr) -> Self {
        if crate::db::error::is_unique_violation(&error) {
            Self::Invalid("update_failed")
        } else {
            Self::Dependency(error)
        }
    }
}

pub mod token_status;
