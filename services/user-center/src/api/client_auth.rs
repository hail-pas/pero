//! Normalize HTTP Basic and form credentials before the shared client authenticator.
use axum::http::{HeaderMap, header};
use base64::Engine;

pub fn apply(
    headers: &HeaderMap,
    client_id: &mut String,
    secret: &mut Option<String>,
) -> Result<(), &'static str> {
    let mut authorization = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = authorization.next() else {
        return Ok(());
    };
    if authorization.next().is_some() || secret.is_some() {
        return Err("Multiple client authentication methods");
    }
    let (_, value) = value
        .to_str()
        .ok()
        .and_then(|v| v.split_once(' '))
        .filter(|(s, _)| s.eq_ignore_ascii_case("Basic"))
        .ok_or("Invalid client authentication")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| "Invalid client authentication")?;
    let decoded = std::str::from_utf8(&decoded).map_err(|_| "Invalid client authentication")?;
    let (id, password) = decoded
        .split_once(':')
        .ok_or("Invalid client authentication")?;
    let decode = |value: &str| -> Result<String, &'static str> {
        let text = format!("v={value}");
        let mut values = url::form_urlencoded::parse(text.as_bytes());
        let (_, result) = values.next().ok_or("Invalid client authentication")?;
        if values.next().is_some() {
            return Err("Invalid client authentication");
        }
        Ok(result.into_owned())
    };
    let id = decode(id)?;
    if id.is_empty() || !client_id.is_empty() && *client_id != id {
        return Err("Invalid client authentication");
    }
    *client_id = id;
    *secret = Some(decode(password)?);
    Ok(())
}

/// Client-authenticated management endpoints share credential rotation and source limits.
pub(super) async fn authenticate(
    state: &crate::state::app::AppState,
    headers: &HeaderMap,
    client_id: &mut String,
    client_secret: &mut Option<String>,
    source: &str,
) -> Result<crate::db::entity::oauth_clients::Model, axum::response::Response> {
    use crate::service::token::{TokenEndpointResult, TokenRequest, TokenService};
    apply(headers, client_id, client_secret)
        .map_err(pero_api_axum::oauth::token_error_unauthorized_response)?;
    let request = TokenRequest {
        grant_type: String::new(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: None,
        client_id: client_id.clone(),
        client_secret: client_secret.clone(),
    };
    TokenService::new(state)
        .authenticate_endpoint(&request, source, 6000)
        .await
        .map_err(|error| match error {
            TokenEndpointResult::Error { code, desc } => {
                pero_api_axum::oauth::token_error_response(code, desc.as_deref())
            }
            TokenEndpointResult::Unauthorized(desc) => {
                pero_api_axum::oauth::token_error_unauthorized_response(&desc)
            }
            TokenEndpointResult::Success(_) => unreachable!(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic_decodes_form_components_and_rejects_mixed_credentials() {
        let mut headers = HeaderMap::new();
        let value = base64::engine::general_purpose::STANDARD.encode("client%3Aid:a%2Bb%3Ac");
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {value}").parse().unwrap(),
        );
        let (mut id, mut secret) = (String::new(), None);
        apply(&headers, &mut id, &mut secret).unwrap();
        assert_eq!(id, "client:id");
        assert_eq!(secret.as_deref(), Some("a+b:c"));
        assert!(apply(&headers, &mut id, &mut secret).is_err());
        assert!(apply(&headers, &mut "other".into(), &mut None).is_err());
    }
}
