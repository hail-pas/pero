use crate::domain::social::entity::SocialProvider;
use crate::domain::social::entity::SocialUserInfo;
use crate::domain::social::error::social_login_failed;
use crate::domain::social::http::HttpClient;
use crate::shared::error::AppError;

pub async fn exchange_code(
    http: &dyn HttpClient,
    provider: &SocialProvider,
    code: &str,
    redirect_uri: &str,
) -> Result<String, AppError> {
    let resp = http.post_form(
        &provider.token_url,
        vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &provider.client_id),
            ("client_secret", &provider.client_secret),
            ("redirect_uri", redirect_uri),
        ],
    )
    .await
    .map_err(|_| social_login_failed("token exchange returned error"))?;

    resp["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| social_login_failed("token response missing access_token"))
}

pub async fn fetch_userinfo(
    http: &dyn HttpClient,
    provider: &SocialProvider,
    access_token: &str,
) -> Result<SocialUserInfo, AppError> {
    let raw = http.get_bearer(&provider.userinfo_url, access_token)
        .await
        .map_err(|_| social_login_failed("userinfo request returned error"))?;

    let mut info = map_userinfo_response(&provider.name, &raw)?;
    if provider.name == "github" && info.email.is_none() {
        if let Ok(github_resp) = http.get_bearer("https://api.github.com/user/emails", access_token).await {
            info.email = extract_github_primary_email(&github_resp);
            info.email_verified = info.email.is_some();
        }
    }

    Ok(info)
}

fn extract_github_primary_email(raw: &serde_json::Value) -> Option<String> {
    raw.as_array()?.iter().find_map(|e| {
        if e["primary"].as_bool()? && e["verified"].as_bool()? {
            e["email"].as_str().map(String::from)
        } else {
            None
        }
    })
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
