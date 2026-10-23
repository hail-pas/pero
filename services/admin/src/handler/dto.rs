#[derive(Debug, serde::Serialize)]
pub struct AdminLoginView {
    pub error: String,
    pub authorize_url: String,
}

#[derive(Debug, serde::Serialize)]
pub struct AdminHomeView {
    pub csrf_token: String,
    pub username: String,
    pub email: String,
    pub picture: String,
    pub profile_url: String,
    pub password_url: String,
    pub issuer: String,
}
