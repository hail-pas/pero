use crate::shared::error::AppError;
use sqlx::postgres::PgPool;

#[derive(Debug, Clone, Copy)]
pub enum Table {
    Users,
    Apps,
    OAuth2Clients,
    Policies,
}

impl Table {
    fn name(&self) -> &'static str {
        match self {
            Table::Users => "users",
            Table::Apps => "apps",
            Table::OAuth2Clients => "oauth2_clients",
            Table::Policies => "policies",
        }
    }

    fn order(&self) -> &'static str {
        match self {
            Table::Users => "created_at DESC",
            Table::Apps => "created_at DESC",
            Table::OAuth2Clients => "created_at DESC",
            Table::Policies => "priority DESC",
        }
    }
}

pub const USERS: Table = Table::Users;
pub const APPS: Table = Table::Apps;
pub const OAUTH2_CLIENTS: Table = Table::OAuth2Clients;
pub const POLICIES: Table = Table::Policies;

pub async fn paginate<T>(
    pool: &PgPool,
    table: Table,
    page: i64,
    page_size: i64,
) -> Result<(Vec<T>, i64), AppError>
where
    T: for<'q> sqlx::FromRow<'q, sqlx::postgres::PgRow> + Send + Unpin,
{
    let off = offset(page, page_size);
    let items: Vec<T> = sqlx::query_as(&format!(
        "SELECT * FROM {} ORDER BY {} LIMIT $1 OFFSET $2",
        table.name(),
        table.order()
    ))
    .bind(page_size)
    .bind(off)
    .fetch_all(pool)
    .await?;
    let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {}", table.name()))
        .fetch_one(pool)
        .await?;
    Ok((items, total))
}

pub fn offset(page: i64, page_size: i64) -> i64 {
    (page - 1) * page_size
}
