use base64::Engine;
use rand::Rng;

use crate::encode::append_query_param;

pub fn generate_state() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    crate::crypto::sha256_hex(&token)
}

pub struct AuthorizeUrlParams<'a> {
    pub endpoint: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub state: &'a str,
    pub code_challenge: &'a str,
    pub prompt: Option<&'a str>,
}

pub fn build_authorize_url(params: &AuthorizeUrlParams<'_>) -> String {
    let mut url = params.endpoint.to_owned();
    append_query_param(&mut url, "response_type", "code");
    append_query_param(&mut url, "client_id", params.client_id);
    append_query_param(&mut url, "redirect_uri", params.redirect_uri);
    if !params.scope.is_empty() {
        append_query_param(&mut url, "scope", params.scope);
    }
    append_query_param(&mut url, "state", params.state);
    append_query_param(&mut url, "code_challenge", params.code_challenge);
    append_query_param(&mut url, "code_challenge_method", "S256");
    if let Some(prompt) = params.prompt {
        append_query_param(&mut url, "prompt", prompt);
    }
    url
}

pub fn build_code_redirect_url(redirect_uri: &str, code: &str, state: Option<&str>) -> String {
    let mut url = redirect_uri.to_owned();
    append_query_param(&mut url, "code", code);
    if let Some(s) = state {
        append_query_param(&mut url, "state", s);
    }
    url
}

pub fn build_error_redirect_url(
    redirect_uri: &str,
    error: &str,
    error_description: Option<&str>,
    state: Option<&str>,
) -> String {
    let mut url = redirect_uri.to_owned();
    append_query_param(&mut url, "error", error);
    if let Some(desc) = error_description {
        append_query_param(&mut url, "error_description", desc);
    }
    if let Some(s) = state {
        append_query_param(&mut url, "state", s);
    }
    url
}

/// Append an endpoint path without changing the issuer used for JWT validation.
pub fn issuer_endpoint(issuer: &str, path: &str) -> String {
    format!(
        "{}/{}",
        issuer.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn endpoints_preserve_issuer_path_prefix() {
        for issuer in ["https://id.example/tenant", "https://id.example/tenant/"] {
            assert_eq!(
                super::issuer_endpoint(issuer, "/api/oauth2/token"),
                "https://id.example/tenant/api/oauth2/token"
            );
        }
    }
    #[test]
    fn endpoint_queries_preserve_paths_and_encode_values() {
        for base in [
            "https://id.example",
            "https://id.example/",
            "https://id.example/tenant",
            "https://id.example/tenant/",
        ] {
            let mut link = super::issuer_endpoint(base, "account/profile/verify-contact");
            super::append_query_param(&mut link, "nonce", "a&b+c#d");
            let parsed = url::Url::parse(&link).unwrap();
            assert!(!parsed.path().contains("//"));
            assert_eq!(
                parsed.path().starts_with("/tenant/"),
                base.contains("tenant")
            );
            assert_eq!(
                parsed.query_pairs().collect::<Vec<_>>(),
                vec![("nonce".into(), "a&b+c#d".into())]
            );
        }
    }
}
