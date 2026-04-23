use crate::domain::identity::models::User;
use crate::shared::constants::oauth2::scopes as oauth2_scopes;

pub struct ScopedClaims {
    pub name: Option<String>,
    pub nickname: Option<String>,
    pub picture: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
}

impl ScopedClaims {
    pub fn from_user_and_scopes(user: &User, scopes: &[String]) -> Self {
        let has = |s: &str| scopes.iter().any(|sc| sc == s);
        Self {
            name: if has(oauth2_scopes::PROFILE) {
                Some(user.username.clone())
            } else {
                None
            },
            nickname: if has(oauth2_scopes::PROFILE) {
                user.nickname.clone()
            } else {
                None
            },
            picture: if has(oauth2_scopes::PROFILE) {
                user.avatar_url.clone()
            } else {
                None
            },
            email: if has(oauth2_scopes::EMAIL) {
                Some(user.email.clone())
            } else {
                None
            },
            email_verified: if has(oauth2_scopes::EMAIL) {
                Some(user.email_verified)
            } else {
                None
            },
            phone_number: if has(oauth2_scopes::PHONE) {
                user.phone.clone()
            } else {
                None
            },
            phone_number_verified: if has(oauth2_scopes::PHONE) {
                Some(user.phone.is_some())
            } else {
                None
            },
        }
    }
}
