use crate::domain::auth::repo::SessionStore;
use crate::domain::oauth::repo::OAuth2TokenStore;
use crate::shared::error::AppError;
use uuid::Uuid;

pub struct SessionBinding {
    pub user_id: Uuid,
    pub session_id: Option<String>,
}

impl SessionBinding {
    pub async fn revoke_all(
        &self,
        sessions: &dyn SessionStore,
        tokens: &dyn OAuth2TokenStore,
    ) -> Result<(), AppError> {
        if let Some(ref sid) = self.session_id {
            let _ = sessions.revoke(sid).await;
        }
        tokens.revoke_all_for_user(self.user_id).await?;
        Ok(())
    }

    pub async fn revoke_session_only(&self, sessions: &dyn SessionStore) -> Result<(), AppError> {
        if let Some(ref sid) = self.session_id {
            sessions.revoke(sid).await?;
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
