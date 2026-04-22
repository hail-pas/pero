use serde::Serialize;
use utoipa::ToSchema;

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

#[derive(Debug, Serialize, ToSchema)]
pub struct PageData<T: Serialize + ToSchema> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

impl<T: Serialize + ToSchema> PageData<T> {
    pub fn new(items: Vec<T>, total: i64, page: i64, page_size: i64) -> Self {
        Self {
            items,
            total,
            page,
            page_size,
        }
    }
}
