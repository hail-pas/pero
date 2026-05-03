use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse {
    pub code: i32,
    pub message: String,
}

impl MessageResponse {
    pub fn success(message: &str) -> Self {
        Self {
            code: 0,
            message: message.into(),
        }
    }
}
