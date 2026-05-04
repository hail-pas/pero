use crate::domain::federation::http::HttpClient;
use crate::shared::error::AppError;

pub struct ReqwestHttpClient;

#[async_trait::async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn post_form(
        &self,
        url: &str,
        fields: Vec<(&str, &str)>,
    ) -> Result<serde_json::Value, AppError> {
        let client = reqwest::Client::new();
        let resp = client
            .post(url)
            .header("Accept", "application/json")
            .form(&fields)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("HTTP POST failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(url, status = %status, body = %body, "HTTP POST returned error");
            return Err(AppError::Internal(format!(
                "HTTP POST {url} returned {status}"
            )));
        }

        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("HTTP response parse failed: {e}")))
    }

    async fn get_bearer(
        &self,
        url: &str,
        access_token: &str,
    ) -> Result<serde_json::Value, AppError> {
        let client = reqwest::Client::new();
        let resp = client
            .get(url)
            .header("User-Agent", "Pero/1.0")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("HTTP GET failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(url, status = %status, body = %body, "HTTP GET returned error");
            return Err(AppError::Internal(format!(
                "HTTP GET {url} returned {status}"
            )));
        }

        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("HTTP response parse failed: {e}")))
    }
}
