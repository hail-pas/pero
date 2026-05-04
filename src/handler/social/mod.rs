pub mod callback;
pub mod initiate;
pub mod management;
pub mod public;

use crate::domain::federation::entity::SocialProviderName;
use crate::shared::state::AppState;

pub fn social_callback_url(issuer: &str, provider: &str) -> String {
    format!(
        "{}/sso/social/{}/callback",
        issuer.trim_end_matches('/'),
        provider
    )
}

#[derive(Debug, Clone)]
pub struct ProviderView {
    pub key: String,
    pub icon: &'static str,
    pub name: String,
}

pub async fn load_provider_views(state: &AppState) -> Vec<ProviderView> {
    match state.repos.social.list_enabled_providers().await {
        Ok(providers) => providers
            .iter()
            .filter_map(|p| {
                let key = SocialProviderName::from_str(&p.name)?;
                Some(ProviderView {
                    key: key.as_str().to_string(),
                    icon: key.svg_icon(),
                    name: p.display_name.clone(),
                })
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}
