use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, ExprTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, sea_query::Expr,
};
use uuid::Uuid;

use crate::config::DASHBOARD_PAGE_SIZE;
use crate::db::entity::{
    apps, identities, identity_provider_keys, identity_providers, oauth_clients, user_app_access,
    users,
};
use crate::db::enums::{CommonStatus, UserStatus};

fn non_empty(s: &str) -> Option<&str> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

// === Apps ===

pub async fn list_apps(
    db: &DatabaseConnection,
    page: u64,
    q: &str,
    status: &str,
    app_type: &str,
) -> Result<(Vec<apps::Model>, u64), DbErr> {
    let mut query = apps::Entity::find().order_by_desc(apps::Column::CreatedAt);

    if let Some(s) = non_empty(status)
        && let Ok(v) = CommonStatus::try_from_str(s)
    {
        query = query.filter(apps::Column::Status.eq(v));
    }
    if let Some(t) = non_empty(app_type)
        && let Ok(v) = crate::db::enums::AppType::try_from_str(t)
    {
        query = query.filter(apps::Column::Type.eq(v));
    }
    if let Some(search) = non_empty(q) {
        let pattern = format!("%{}%", escape_like(search));
        query = query.filter(
            Expr::col(apps::Column::Code)
                .like(&pattern)
                .or(Expr::col(apps::Column::Name).like(&pattern)),
        );
    }

    pero_db_seaorm::paginate!(query, db, page, DASHBOARD_PAGE_SIZE)
}

pub async fn find_app_by_id(
    db: &DatabaseConnection,
    id: Uuid,
) -> Result<Option<apps::Model>, DbErr> {
    apps::Entity::find_by_id(id).one(db).await
}

pub async fn list_clients_by_app(
    db: &DatabaseConnection,
    app_id: Uuid,
) -> Result<Vec<oauth_clients::Model>, DbErr> {
    oauth_clients::Entity::find()
        .filter(oauth_clients::Column::AppId.eq(app_id))
        .order_by_asc(oauth_clients::Column::CreatedAt)
        .all(db)
        .await
}

// === Users ===

pub async fn list_users(
    db: &DatabaseConnection,
    page: u64,
    q: &str,
    status: &str,
) -> Result<(Vec<users::Model>, u64), DbErr> {
    let mut query = users::Entity::find()
        .filter(users::Column::DeletedAt.is_null())
        .order_by_desc(users::Column::CreatedAt);

    if let Some(s) = non_empty(status)
        && let Ok(v) = UserStatus::try_from_str(s)
    {
        query = query.filter(users::Column::Status.eq(v));
    }
    if let Some(search) = non_empty(q) {
        let pattern = format!("%{}%", escape_like(search));
        query = query.filter(
            Expr::col(users::Column::Username)
                .like(&pattern)
                .or(Expr::col(users::Column::Email).like(&pattern))
                .or(Expr::col(users::Column::Phone).like(&pattern)),
        );
    }

    pero_db_seaorm::paginate!(query, db, page, DASHBOARD_PAGE_SIZE)
}

pub async fn find_user_by_id(
    db: &DatabaseConnection,
    id: Uuid,
) -> Result<Option<users::Model>, DbErr> {
    users::Entity::find_by_id(id).one(db).await
}

pub async fn list_user_identities(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<Vec<identities::Model>, DbErr> {
    identities::Entity::find()
        .filter(identities::Column::UserId.eq(user_id))
        .filter(identities::Column::UnboundAt.is_null())
        .all(db)
        .await
}

pub async fn list_user_access(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<Vec<(user_app_access::Model, apps::Model)>, DbErr> {
    let access_rows = user_app_access::Entity::find()
        .filter(user_app_access::Column::UserId.eq(user_id))
        .all(db)
        .await?;

    let app_ids: Vec<Uuid> = access_rows.iter().map(|a| a.app_id).collect();
    let mut apps_map: std::collections::HashMap<Uuid, apps::Model> = if app_ids.is_empty() {
        std::collections::HashMap::new()
    } else {
        apps::Entity::find()
            .filter(apps::Column::Id.is_in(app_ids))
            .all(db)
            .await?
            .into_iter()
            .map(|a| (a.id, a))
            .collect()
    };

    let mut result = Vec::with_capacity(access_rows.len());
    for a in access_rows {
        if let Some(app) = apps_map.remove(&a.app_id) {
            result.push((a, app));
        }
    }
    Ok(result)
}

pub async fn list_all_apps_brief(
    db: &DatabaseConnection,
) -> Result<Vec<(Uuid, String, String)>, DbErr> {
    let all = apps::Entity::find()
        .filter(apps::Column::Status.eq(CommonStatus::Active))
        .order_by_asc(apps::Column::Name)
        .all(db)
        .await?;
    Ok(all.into_iter().map(|a| (a.id, a.code, a.name)).collect())
}

// === Providers ===

pub async fn list_providers(
    db: &DatabaseConnection,
    page: u64,
) -> Result<(Vec<identity_providers::Model>, u64), DbErr> {
    let query =
        identity_providers::Entity::find().order_by_asc(identity_providers::Column::CreatedAt);
    pero_db_seaorm::paginate!(query, db, page, DASHBOARD_PAGE_SIZE)
}

pub async fn find_provider_by_id(
    db: &DatabaseConnection,
    id: Uuid,
) -> Result<Option<identity_providers::Model>, DbErr> {
    identity_providers::Entity::find_by_id(id).one(db).await
}

pub async fn list_keys_by_provider(
    db: &DatabaseConnection,
    provider_id: Uuid,
) -> Result<Vec<identity_provider_keys::Model>, DbErr> {
    identity_provider_keys::Entity::find()
        .filter(identity_provider_keys::Column::ProviderId.eq(provider_id))
        .order_by_desc(identity_provider_keys::Column::CreatedAt)
        .all(db)
        .await
}
