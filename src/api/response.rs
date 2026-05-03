use serde::Serialize;
use utoipa::ToSchema;

pub use crate::shared::message::MessageResponse;
pub use crate::shared::page::PageData;

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiResponse<T: Serialize + ToSchema> {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize + ToSchema> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            code: 0,
            message: "ok".into(),
            data: Some(data),
        }
    }
}
