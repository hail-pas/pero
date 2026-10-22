pub mod access;
pub mod account;
pub mod app;
pub mod client;
pub mod contact;
pub mod login;
pub mod logout;
pub mod notify;
pub mod oauth;
pub mod password;
pub mod provider;
pub mod recovery;
pub mod scope;
pub mod session;
pub mod social;
pub mod token;
pub mod user;
pub mod verification;

#[derive(Debug, thiserror::Error)]
pub enum ManagementError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("Management dependency unavailable")]
    Dependency(sea_orm::DbErr),
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
