use crate::domain::identity::session;
use crate::domain::oauth2::store::RefreshTokenRepo;
use crate::infra::cache::Pool;
use crate::shared::error::AppError;
use sqlx::postgres::PgPool;
use uuid::Uuid;

pub struct SessionBinding {
    pub user_id: Uuid,
    pub session_id: Option<String>,
}

impl SessionBinding {
    pub async fn revoke_all(&self, cache: &Pool, db: &PgPool) -> Result<(), AppError> {
        if let Some(ref sid) = self.session_id {
            let _ = session::revoke_session(cache, sid).await;
        }
        RefreshTokenRepo::revoke_all_for_user(db, self.user_id).await?;
        Ok(())
    }

    pub async fn revoke_session_only(&self, cache: &Pool) -> Result<(), AppError> {
        if let Some(ref sid) = self.session_id {
            session::revoke_session(cache, sid).await?;
        }
        Ok(())
    }

    pub fn from_sid(user_id: Uuid, session_id: impl Into<String>) -> Self {
        Self {
            user_id,
            session_id: Some(session_id.into()),
        }
    }

    pub fn user_only(user_id: Uuid) -> Self {
        Self {
            user_id,
            session_id: None,
        }
    }
}
