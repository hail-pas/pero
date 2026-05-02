use serde::Deserialize;
use tracing;

use crate::domain::social::entity::SocialProvider;
use crate::domain::social::entity::SocialUserInfo;
use crate::domain::social::error::social_login_failed;
use crate::shared::error::AppError;

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

pub async fn exchange_code(
    provider: &SocialProvider,
    code: &str,
    redirect_uri: &str,
) -> Result<String, crate::shared::error::AppError> {
    let client = reqwest::Client::new();
    let resp = client
        .post(&provider.token_url)
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &provider.client_id),
            ("client_secret", &provider.client_secret),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await
        .map_err(|e| social_login_failed(&format!("token request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        tracing::warn!(provider = %provider.name, status = %status, body = %body, "token exchange failed");
        return Err(social_login_failed("token exchange returned error"));
    }

    let token: TokenResponse = resp
        .json()
        .await
        .map_err(|e| social_login_failed(&format!("token response parse failed: {e}")))?;

    Ok(token.access_token)
}

pub async fn fetch_userinfo(
    provider: &SocialProvider,
    access_token: &str,
) -> Result<SocialUserInfo, crate::shared::error::AppError> {
    let client = reqwest::Client::new();
    let resp = client
        .get(&provider.userinfo_url)
        .header("User-Agent", "Pero/1.0")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| social_login_failed(&format!("userinfo request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        tracing::warn!(provider = %provider.name, status = %status, body = %body, "userinfo request failed");
        return Err(social_login_failed("userinfo request returned error"));
    }

    let raw: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| social_login_failed(&format!("userinfo parse failed: {e}")))?;

    let mut info = map_userinfo_response(&provider.name, &raw)?;
    if provider.name == "github" && info.email.is_none() {
        if let Some((email, verified)) = fetch_github_email(&client, access_token).await {
            info.email = Some(email);
            info.email_verified = verified;
        }
    }

    Ok(info)
}

pub fn map_userinfo_response(
    provider_name: &str,
    raw: &serde_json::Value,
) -> Result<SocialUserInfo, AppError> {
    let info = match provider_name {
        "github" => {
            let id = raw["id"]
                .as_i64()
                .map(|v| v.to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| social_login_failed("userinfo missing provider id"))?;
            map_github(raw, id)
        }
        "google" => {
            let id = raw["sub"]
                .as_str()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| social_login_failed("userinfo missing provider id"))?;
            map_google(raw, id)
        }
        _ => {
            let id = raw["id"]
                .as_str()
                .map(str::to_string)
                .or_else(|| raw["id"].as_i64().map(|v| v.to_string()))
                .filter(|v| !v.is_empty())
                .ok_or_else(|| social_login_failed("userinfo missing provider id"))?;
            map_generic(raw, provider_name, id)
        }
    };

    Ok(info)
}

async fn fetch_github_email(client: &reqwest::Client, access_token: &str) -> Option<(String, bool)> {
    #[derive(Debug, serde::Deserialize)]
    struct GitHubEmail {
        email: String,
        primary: bool,
        verified: bool,
    }

    let resp = client
        .get("https://api.github.com/user/emails")
        .header("User-Agent", "Pero/1.0")
        .bearer_auth(access_token)
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let emails: Vec<GitHubEmail> = resp.json().await.ok()?;
    emails
        .iter()
        .find(|e| e.primary && e.verified)
        .map(|e| (e.email.clone(), true))
}

fn map_github(raw: &serde_json::Value, provider_uid: String) -> SocialUserInfo {
    SocialUserInfo {
        provider: "github".into(),
        provider_uid,
        email: raw["email"].as_str().map(String::from),
        email_verified: false,
        username: raw["login"].as_str().map(String::from),
        display_name: raw["name"].as_str().map(String::from),
        avatar_url: raw["avatar_url"].as_str().map(String::from),
    }
}

fn map_google(raw: &serde_json::Value, provider_uid: &str) -> SocialUserInfo {
    SocialUserInfo {
        provider: "google".into(),
        provider_uid: provider_uid.to_string(),
        email: raw["email"].as_str().map(String::from),
        email_verified: raw["email_verified"].as_bool().unwrap_or(false),
        username: None,
        display_name: raw["name"].as_str().map(String::from),
        avatar_url: raw["picture"].as_str().map(String::from),
    }
}

fn map_generic(
    raw: &serde_json::Value,
    provider_name: &str,
    provider_uid: String,
) -> SocialUserInfo {
    SocialUserInfo {
        provider: provider_name.into(),
        provider_uid,
        email: raw["email"].as_str().map(String::from),
        email_verified: raw["email_verified"].as_bool().unwrap_or(false),
        username: raw["username"]
            .as_str()
            .or_else(|| raw["login"].as_str())
            .map(String::from),
        display_name: raw["name"].as_str().map(String::from),
        avatar_url: raw["avatar_url"]
            .as_str()
            .or_else(|| raw["picture"].as_str())
            .map(String::from),
    }
}
