use crate::infra::cache;
use crate::infra::cache::Pool;
use crate::shared::constants::cache_keys;
use crate::shared::error::AppError;
use uuid::Uuid;

pub struct AbacCache;

impl AbacCache {
    fn policy_key(user_id: Uuid, app_id: Option<Uuid>) -> String {
        match app_id {
            Some(aid) => format!("{}{}:{}", cache_keys::ABAC_PREFIX, user_id, aid),
            None => format!("{}{}:", cache_keys::ABAC_PREFIX, user_id),
        }
    }

    fn policy_version_key(user_id: Uuid, app_id: Option<Uuid>) -> String {
        format!(
            "{}{}:{}:v",
            cache_keys::ABAC_PREFIX,
            user_id,
            match app_id {
                Some(aid) => aid.to_string(),
                None => String::new(),
            }
        )
    }

    fn subject_key(user_id: Uuid) -> String {
        format!("{}{}", cache_keys::ABAC_SUBJECT_PREFIX, user_id)
    }

    fn subject_version_key(user_id: Uuid) -> String {
        format!("{}{}:sv", cache_keys::ABAC_SUBJECT_PREFIX, user_id)
    }

    fn app_version_key(app_id: Option<Uuid>) -> String {
        match app_id {
            Some(aid) => format!("{}app:{}:v", cache_keys::ABAC_PREFIX, aid),
            None => format!("{}app::v", cache_keys::ABAC_PREFIX),
        }
    }

    async fn read_versioned<T: serde::de::DeserializeOwned>(
        pool: &Pool,
        base_key: &str,
        version_key: &str,
    ) -> Result<Option<T>, AppError> {
        let version: Option<String> = cache::get(pool, version_key).await?;
        match version {
            Some(v) => {
                let keyed = format!("{}:{}", base_key, v);
                cache::get_json(pool, &keyed).await
            }
            None => Ok(None),
        }
    }

    async fn write_versioned<T: serde::Serialize>(
        pool: &Pool,
        base_key: &str,
        version_key: &str,
        value: &T,
        ttl: i64,
    ) -> Result<(), AppError> {
        let version = Uuid::new_v4().to_string();
        let keyed = format!("{}:{}", base_key, version);
        cache::set_json(pool, &keyed, value, ttl).await?;
        cache::set(pool, version_key, &version, ttl).await?;
        Ok(())
    }

    async fn bump_version(pool: &Pool, version_key: &str, ttl: i64) -> Result<(), AppError> {
        let new_version = Uuid::new_v4().to_string();
        cache::set(pool, version_key, &new_version, ttl).await
    }

    pub async fn get_policies<T: serde::de::DeserializeOwned>(
        pool: &Pool,
        user_id: Uuid,
        app_id: Option<Uuid>,
    ) -> Result<Option<T>, AppError> {
        Self::read_versioned(
            pool,
            &Self::policy_key(user_id, app_id),
            &Self::policy_version_key(user_id, app_id),
        )
        .await
    }

    pub async fn set_policies<T: serde::Serialize>(
        pool: &Pool,
        user_id: Uuid,
        app_id: Option<Uuid>,
        value: &T,
        ttl: i64,
    ) -> Result<(), AppError> {
        Self::write_versioned(
            pool,
            &Self::policy_key(user_id, app_id),
            &Self::policy_version_key(user_id, app_id),
            value,
            ttl,
        )
        .await
    }

    pub async fn get_subject_attrs<T: serde::de::DeserializeOwned>(
        pool: &Pool,
        user_id: Uuid,
    ) -> Result<Option<T>, AppError> {
        Self::read_versioned(
            pool,
            &Self::subject_key(user_id),
            &Self::subject_version_key(user_id),
        )
        .await
    }

    pub async fn set_subject_attrs<T: serde::Serialize>(
        pool: &Pool,
        user_id: Uuid,
        value: &T,
        ttl: i64,
    ) -> Result<(), AppError> {
        Self::write_versioned(
            pool,
            &Self::subject_key(user_id),
            &Self::subject_version_key(user_id),
            value,
            ttl,
        )
        .await
    }

    pub async fn invalidate_policy_version(
        pool: &Pool,
        app_id: Option<Uuid>,
        ttl: i64,
    ) -> Result<(), AppError> {
        Self::bump_version(pool, &Self::app_version_key(app_id), ttl).await
    }

    pub async fn invalidate_user_policy_version(
        pool: &Pool,
        user_id: Uuid,
        ttl: i64,
    ) -> Result<(), AppError> {
        Self::bump_version(pool, &Self::policy_version_key(user_id, None), ttl).await?;
        Self::bump_version(pool, &Self::subject_version_key(user_id), ttl).await
    }
}
