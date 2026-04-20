use crate::domains::identity::helpers;
use crate::domains::identity::models::User;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

pub struct AuthService;

impl AuthService {
    pub async fn register_user_with_password(
        state: &AppState,
        username: &str,
        email: &str,
        phone: Option<&str>,
        nickname: Option<&str>,
        password: &str,
    ) -> Result<User, AppError> {
        let mut tx = state.db.begin().await?;
        let user = helpers::create_user_with_password(
            &mut tx, username, email, phone, nickname, password,
        )
        .await?;
        tx.commit().await?;
        Ok(user)
    }
}
