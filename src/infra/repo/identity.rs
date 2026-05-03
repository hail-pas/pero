use std::sync::Arc;

use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::domain::identity::error;
use crate::domain::identity::models::{Identity, UpdateMeRequest, UpdateUserRequest, User};
use crate::domain::identity::repo::{IdentityStore, UserAttributeStore, UserStore};
use crate::domain::identity::dto::{AttributeItem, UserAttribute};
use crate::shared::error::{AppError, require_found};
use crate::shared::pagination::{USERS, paginate};

pub struct SqlxUserStore {
    pool: Arc<PgPool>,
}

impl SqlxUserStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

pub struct SqlxIdentityStore {
    pool: Arc<PgPool>,
}

impl SqlxIdentityStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

pub struct SqlxUserAttributeStore {
    pool: Arc<PgPool>,
}

impl SqlxUserAttributeStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for SqlxUserStore {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AppError> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, AppError> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn find_by_phone(&self, phone: &str) -> Result<Option<User>, AppError> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE phone = $1")
            .bind(phone)
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn list(&self, page: i64, page_size: i64) -> Result<(Vec<User>, i64), AppError> {
        paginate(&self.pool, USERS, page, page_size).await
    }

    async fn update_admin(
        &self,
        id: Uuid,
        req: &UpdateUserRequest,
        reset_email_verified: bool,
        reset_phone_verified: bool,
    ) -> Result<User, AppError> {
        let mut builder =
            sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE users SET updated_at = now()");
        if reset_email_verified {
            builder.push(", email_verified = false");
        }
        if reset_phone_verified {
            builder.push(", phone_verified = false");
        }
        req.username.push_column(&mut builder, "username");
        req.email.push_column(&mut builder, "email");
        req.phone.push_column(&mut builder, "phone");
        req.nickname.push_column(&mut builder, "nickname");
        req.avatar_url.push_column(&mut builder, "avatar_url");
        req.status.push_column(&mut builder, "status");
        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(" RETURNING *");
        let result = builder
            .build_query_as::<User>()
            .fetch_optional(&*self.pool)
            .await?;
        require_found(result, "user")
    }

    async fn update_self(
        &self,
        id: Uuid,
        req: &UpdateMeRequest,
        reset_email_verified: bool,
        reset_phone_verified: bool,
    ) -> Result<User, AppError> {
        let mut builder =
            sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE users SET updated_at = now()");
        if reset_email_verified {
            builder.push(", email_verified = false");
        }
        if reset_phone_verified {
            builder.push(", phone_verified = false");
        }
        req.email.push_column(&mut builder, "email");
        req.nickname.push_column(&mut builder, "nickname");
        req.avatar_url.push_column(&mut builder, "avatar_url");
        req.phone.push_column(&mut builder, "phone");
        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(" RETURNING *");
        let result = builder
            .build_query_as::<User>()
            .fetch_optional(&*self.pool)
            .await?;
        require_found(result, "user")
    }

    async fn delete(&self, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(error::user_not_found());
        }
        Ok(())
    }

    async fn set_email_verified(&self, user_id: Uuid, email: &str) -> Result<(), AppError> {
        let result = sqlx::query(
            "UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1 AND email = $2",
        )
        .bind(user_id)
        .bind(email)
        .execute(&*self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(error::user_not_found());
        }
        Ok(())
    }

    async fn set_phone_verified(&self, user_id: Uuid, phone: &str) -> Result<(), AppError> {
        let result = sqlx::query(
            "UPDATE users SET phone_verified = true, updated_at = now() WHERE id = $1 AND phone = $2",
        )
        .bind(user_id)
        .bind(phone)
        .execute(&*self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(error::user_not_found());
        }
        Ok(())
    }

    async fn check_new_user_conflicts(
        &self,
        username: &str,
        email: Option<&str>,
        phone: Option<&str>,
    ) -> Result<(), AppError> {
        #[derive(sqlx::FromRow)]
        struct Check {
            username_exists: bool,
            email_exists: bool,
            phone_exists: bool,
        }
        let check: Check = sqlx::query_as(
            "SELECT \
                EXISTS(SELECT 1 FROM users WHERE username = $1) AS username_exists, \
                COALESCE(($2::text IS NOT NULL AND EXISTS(SELECT 1 FROM users WHERE email = $2)), false) AS email_exists, \
                COALESCE(($3::text IS NOT NULL AND EXISTS(SELECT 1 FROM users WHERE phone = $3)), false) AS phone_exists"
        )
        .bind(username)
        .bind(email)
        .bind(phone)
        .fetch_one(&*self.pool)
        .await?;
        if check.username_exists {
            return Err(error::username_exists(username));
        }
        if check.email_exists {
            return Err(error::email_exists(email.unwrap_or("")));
        }
        if check.phone_exists {
            return Err(error::phone_exists(phone.unwrap_or("")));
        }
        Ok(())
    }

    async fn check_update_user_conflicts(
        &self,
        id: Uuid,
        username: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
    ) -> Result<(), AppError> {
        #[derive(sqlx::FromRow)]
        struct Check {
            username_conflict: bool,
            email_conflict: bool,
            phone_conflict: bool,
        }
        let check: Check = sqlx::query_as(
            "SELECT \
                COALESCE(($1::text IS NOT NULL AND EXISTS(SELECT 1 FROM users WHERE username = $1 AND id != $4)), false) AS username_conflict, \
                COALESCE(($2::text IS NOT NULL AND EXISTS(SELECT 1 FROM users WHERE email = $2 AND id != $4)), false) AS email_conflict, \
                COALESCE(($3::text IS NOT NULL AND EXISTS(SELECT 1 FROM users WHERE phone = $3 AND id != $4)), false) AS phone_conflict"
        )
        .bind(username)
        .bind(email)
        .bind(phone)
        .bind(id)
        .fetch_one(&*self.pool)
        .await?;
        if check.username_conflict {
            return Err(error::username_exists(username.unwrap_or("")));
        }
        if check.email_conflict {
            return Err(error::email_exists(email.unwrap_or("")));
        }
        if check.phone_conflict {
            return Err(error::phone_exists(phone.unwrap_or("")));
        }
        Ok(())
    }

    async fn create_with_password(
        &self,
        username: &str,
        email: Option<&str>,
        phone: Option<&str>,
        nickname: Option<&str>,
        password_hash: &str,
    ) -> Result<User, AppError> {
        let mut tx = self.pool.begin().await?;
        {
            #[derive(sqlx::FromRow)]
            struct Check {
                username_exists: bool,
                email_exists: bool,
                phone_exists: bool,
            }
            let check: Check = sqlx::query_as(
                "SELECT \
                    EXISTS(SELECT 1 FROM users WHERE username = $1) AS username_exists, \
                    COALESCE(($2::text IS NOT NULL AND EXISTS(SELECT 1 FROM users WHERE email = $2)), false) AS email_exists, \
                    COALESCE(($3::text IS NOT NULL AND EXISTS(SELECT 1 FROM users WHERE phone = $3)), false) AS phone_exists"
            )
            .bind(username)
            .bind(email)
            .bind(phone)
            .fetch_one(&mut *tx)
            .await?;
            if check.username_exists {
                return Err(error::username_exists(username));
            }
            if check.email_exists {
                return Err(error::email_exists(email.unwrap_or("")));
            }
            if check.phone_exists {
                return Err(error::phone_exists(phone.unwrap_or("")));
            }
        }
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (username, email, phone, nickname) VALUES ($1, $2, $3, $4) RETURNING *"
        )
        .bind(username)
        .bind(email)
        .bind(phone)
        .bind(nickname)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query_as::<_, Identity>(
            "INSERT INTO identities (user_id, provider, provider_uid, credential, verified) VALUES ($1, 'password', $1, $2, true) RETURNING *"
        )
        .bind(user.id)
        .bind(password_hash)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(user)
    }

    async fn find_by_social_identity(
        &self,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Option<User>, AppError> {
        let identity = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE provider = $1 AND provider_uid = $2",
        )
        .bind(provider)
        .bind(provider_uid)
        .fetch_optional(&*self.pool)
        .await?;
        match identity {
            Some(id) => {
                let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
                    .bind(id.user_id)
                    .fetch_optional(&*self.pool)
                    .await?;
                Ok(user)
            }
            None => Ok(None),
        }
    }

    async fn link_social_identity(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_uid: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO identities (user_id, provider, provider_uid, verified) VALUES ($1, $2, $3, true)",
        )
        .bind(user_id)
        .bind(provider)
        .bind(provider_uid)
        .execute(&*self.pool)
        .await?;
        sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
            .bind(user_id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    async fn set_email_verified_flag(&self, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
            .bind(user_id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    async fn create_social_user(
        &self,
        username: &str,
        email: Option<&str>,
        nickname: Option<&str>,
        provider: &str,
        provider_uid: &str,
        email_verified: bool,
    ) -> Result<User, AppError> {
        let mut tx = self.pool.begin().await?;

        let resolved_username = {
            let base_username = username;
            let mut resolved = String::new();
            for i in 0..100u32 {
                let candidate = username_candidate(base_username, (i > 0).then_some(i), 64);
                let exists: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
                        .bind(&candidate)
                        .fetch_one(&mut *tx)
                        .await?;
                if !exists {
                    resolved = candidate;
                    break;
                }
            }
            if resolved.is_empty() {
                return Err(AppError::Conflict("could not generate unique username".into()));
            }
            resolved
        };

        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (username, email, phone, nickname) VALUES ($1, $2, $3, $4) RETURNING *"
        )
        .bind(&resolved_username)
        .bind(email)
        .bind(None::<&str>)
        .bind(nickname)
        .fetch_one(&mut *tx)
        .await?;

        if email.is_some() && email_verified {
            sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
                .bind(user.id)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query(
            "INSERT INTO identities (user_id, provider, provider_uid, verified) VALUES ($1, $2, $3, true)",
        )
        .bind(user.id)
        .bind(provider)
        .bind(provider_uid)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(user)
    }

    async fn resolve_unique_username(&self, base: &str) -> Result<String, AppError> {
        for i in 0..100u32 {
            let candidate = username_candidate(base, (i > 0).then_some(i), 64);
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
                    .bind(&candidate)
                    .fetch_one(&*self.pool)
                    .await?;
            if !exists {
                return Ok(candidate);
            }
        }
        Err(AppError::Conflict(
            "could not generate unique username".into(),
        ))
    }
}

fn username_candidate(base: &str, suffix: Option<u32>, max_len: usize) -> String {
    let suffix = suffix.map(|value| format!("_{value}")).unwrap_or_default();
    let base_len = max_len.saturating_sub(suffix.chars().count());
    let truncated: String = base.chars().take(base_len).collect();
    format!("{truncated}{suffix}")
}

#[async_trait::async_trait]
impl IdentityStore for SqlxIdentityStore {
    async fn create_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<Identity, AppError> {
        let identity = sqlx::query_as::<_, Identity>(
            "INSERT INTO identities (user_id, provider, provider_uid, credential, verified) VALUES ($1, 'password', $1, $2, true) RETURNING *"
        )
        .bind(user_id)
        .bind(password_hash)
        .fetch_one(&*self.pool)
        .await?;
        Ok(identity)
    }

    async fn create_social(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Identity, AppError> {
        let identity = sqlx::query_as::<_, Identity>(
            "INSERT INTO identities (user_id, provider, provider_uid, verified) VALUES ($1, $2, $3, true) RETURNING *"
        )
        .bind(user_id)
        .bind(provider)
        .bind(provider_uid)
        .fetch_one(&*self.pool)
        .await?;
        Ok(identity)
    }

    async fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> Result<Option<Identity>, AppError> {
        let identity = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE user_id = $1 AND provider = $2",
        )
        .bind(user_id)
        .bind(provider)
        .fetch_optional(&*self.pool)
        .await?;
        Ok(identity)
    }

    async fn find_by_provider(
        &self,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Option<Identity>, AppError> {
        let identity = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE provider = $1 AND provider_uid = $2",
        )
        .bind(provider)
        .bind(provider_uid)
        .fetch_optional(&*self.pool)
        .await?;
        Ok(identity)
    }

    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<Identity>, AppError> {
        let identities = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await?;
        Ok(identities)
    }

    async fn delete(&self, user_id: Uuid, provider: &str) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM identities WHERE user_id = $1 AND provider = $2")
            .bind(user_id)
            .bind(provider)
            .execute(&*self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(error::identity_not_found());
        }
        Ok(())
    }

    async fn count_by_user(&self, user_id: Uuid) -> Result<i64, AppError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identities WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&*self.pool)
            .await?;
        Ok(count)
    }

    async fn update_credential(
        &self,
        user_id: Uuid,
        provider: &str,
        credential: &str,
    ) -> Result<(), AppError> {
        let result = sqlx::query(
            "UPDATE identities SET credential = $1, updated_at = now() WHERE user_id = $2 AND provider = $3"
        )
        .bind(credential)
        .bind(user_id)
        .bind(provider)
        .execute(&*self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(error::identity_not_found());
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl UserAttributeStore for SqlxUserAttributeStore {
    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<UserAttribute>, AppError> {
        let attrs = sqlx::query_as::<_, UserAttribute>(
            "SELECT * FROM user_attributes WHERE user_id = $1 ORDER BY key",
        )
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await?;
        Ok(attrs)
    }

    async fn upsert(&self, user_id: Uuid, items: &[AttributeItem]) -> Result<(), AppError> {
        if items.is_empty() {
            return Ok(());
        }
        let keys: Vec<&str> = items.iter().map(|i| i.key.as_str()).collect();
        let values: Vec<&str> = items.iter().map(|i| i.value.as_str()).collect();
        sqlx::query(
            "INSERT INTO user_attributes (user_id, key, value)
             SELECT $1, k, v FROM UNNEST($2::text[], $3::text[]) AS t(k, v)
             ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(user_id)
        .bind(&keys)
        .bind(&values)
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    async fn delete_by_user(&self, user_id: Uuid, key: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM user_attributes WHERE user_id = $1 AND key = $2")
            .bind(user_id)
            .bind(key)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }
}
