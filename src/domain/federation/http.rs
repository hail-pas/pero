use crate::shared::error::AppError;

#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    async fn post_form(
        &self,
        url: &str,
        fields: Vec<(&str, &str)>,
    ) -> Result<serde_json::Value, AppError>;

    async fn get_bearer(
        &self,
        url: &str,
        access_token: &str,
    ) -> Result<serde_json::Value, AppError>;
}
