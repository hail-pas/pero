use crate::shared::error::AppError;
use sqlx::postgres::PgPool;

#[derive(Debug, Clone, Copy)]
pub struct TableDef {
    pub table: &'static str,
    pub order: &'static str,
}

pub const USERS: TableDef = TableDef {
    table: "users",
    order: "created_at DESC",
};

pub const APPS: TableDef = TableDef {
    table: "apps",
    order: "created_at DESC",
};

pub const OAUTH2_CLIENTS: TableDef = TableDef {
    table: "oauth2_clients",
    order: "created_at DESC",
};

pub const POLICIES: TableDef = TableDef {
    table: "policies",
    order: "priority DESC",
};

pub async fn paginate<T>(
    pool: &PgPool,
    def: TableDef,
    page: i64,
    page_size: i64,
) -> Result<(Vec<T>, i64), AppError>
where
    T: for<'q> sqlx::FromRow<'q, sqlx::postgres::PgRow> + Send + Unpin,
{
    let off = offset(page, page_size);
    let items: Vec<T> = sqlx::query_as(&format!(
        "SELECT * FROM {} ORDER BY {} LIMIT $1 OFFSET $2",
        def.table, def.order
    ))
    .bind(page_size)
    .bind(off)
    .fetch_all(pool)
    .await?;
    let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {}", def.table))
        .fetch_one(pool)
        .await?;
    Ok((items, total))
}

pub fn offset(page: i64, page_size: i64) -> i64 {
    (page - 1) * page_size
}
