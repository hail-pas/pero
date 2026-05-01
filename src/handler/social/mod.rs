pub mod callback;
pub mod initiate;
pub mod management;
pub mod public;

pub fn social_callback_url(issuer: &str, provider: &str) -> String {
    format!(
        "{}/sso/social/{}/callback",
        issuer.trim_end_matches('/'),
        provider
    )
}
