//! Shared, case-sensitive OAuth scope policy.
pub fn contains(scopes: &[String], scope: &str) -> bool {
    scopes.iter().any(|value| value == scope)
}

pub fn allowed(requested: &[String], allowed: &[String]) -> bool {
    requested.iter().all(|scope| contains(allowed, scope))
}

pub fn user_claims(
    user: &crate::db::entity::users::Model,
    scopes: &[String],
) -> pero_utils::oauth::jwt::IdTokenUser {
    let profile = contains(scopes, "profile");
    let email = contains(scopes, "email");
    let phone = contains(scopes, "phone");
    pero_utils::oauth::jwt::IdTokenUser {
        name: profile.then(|| user.nickname.clone()).flatten(),
        preferred_username: profile.then(|| user.username.clone()),
        picture: profile.then(|| user.avatar_url.clone()).flatten(),
        email: email.then(|| user.email.clone()).flatten(),
        email_verified: email.then_some(user.email_verified_at.is_some()),
        phone: phone.then(|| user.phone.clone()).flatten(),
        phone_verified: phone.then_some(user.phone_verified_at.is_some()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removed_and_custom_scopes_are_not_granted() {
        assert!(!allowed(&["email".into()], &["openid".into()]));
        assert!(!allowed(&["Write".into()], &["write".into()]));
        assert!(!contains(&["OpenID".into()], "openid"));
    }
}

#[cfg(test)]
mod claim_tests {
    #[test]
    fn personally_identifying_claims_require_the_corresponding_scope() {
        use crate::db::{entity::users, enums::UserStatus};
        let now = time::OffsetDateTime::now_utc();
        let user = users::Model {
            id: uuid::Uuid::now_v7(),
            username: "name".into(),
            email: Some("email@example.test".into()),
            email_verified_at: Some(now),
            phone: Some("+123456789".into()),
            phone_verified_at: Some(now),
            nickname: Some("Nick".into()),
            avatar_url: Some("https://example.test/avatar".into()),
            status: UserStatus::Active,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let empty = serde_json::to_value(super::user_claims(&user, &["openid".into()])).unwrap();
        assert_eq!(empty, serde_json::json!({}));
        let email = serde_json::to_value(super::user_claims(&user, &["email".into()])).unwrap();
        assert_eq!(
            email,
            serde_json::json!({"email":"email@example.test","email_verified":true})
        );
        let phone = serde_json::to_value(super::user_claims(&user, &["phone".into()])).unwrap();
        assert_eq!(
            phone,
            serde_json::json!({"phone_number":"+123456789","phone_number_verified":true})
        );
    }
}

/// A replacement refresh token retains the original grant; only the access token is narrowed.
pub fn refresh_scopes(requested: Option<&str>, granted: &[String]) -> Option<Vec<String>> {
    let Some(requested) = requested else {
        return Some(granted.to_vec());
    };
    let scopes: Vec<String> = requested
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if scopes.is_empty()
        || scopes.iter().any(|s| {
            s.bytes()
                .any(|b| !(b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b)))
        })
        || !allowed(&scopes, granted)
    {
        return None;
    }
    Some(scopes)
}
