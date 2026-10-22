use askama::Template;

#[derive(Debug, Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: String,
    pub authorize_url: String,
}

#[derive(Debug, Template)]
#[template(path = "home.html")]
pub struct HomeTemplate {
    pub username: String,
    pub email: String,
    pub picture: String,
    pub profile_url: String,
    pub password_url: String,
    pub issuer: String,
}
