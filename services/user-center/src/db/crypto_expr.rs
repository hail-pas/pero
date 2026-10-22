use crate::config;
use sea_orm::sea_query::{Alias, Expr, Func, SimpleExpr};

const PGP_OPTIONS: &str = "cipher-algo=aes256,compress-algo=0";

fn app_encrypt_key_expr() -> Expr {
    Func::cust(Alias::new("current_setting"))
        .arg::<&str>(config::ENCRYPT_KEY_CONFIG_KEY)
        .into()
}

pub fn pgp_encrypt_expr(plaintext: impl Into<String>) -> SimpleExpr {
    let encrypted: Expr = Func::cust(Alias::new("pgp_sym_encrypt"))
        .args([
            Expr::val(plaintext.into()),
            app_encrypt_key_expr(),
            Expr::val(PGP_OPTIONS),
        ])
        .into();
    Func::cust(Alias::new("armor")).arg(encrypted).into()
}

pub fn pgp_decrypt_expr(col: Expr) -> SimpleExpr {
    let armored: Expr = Func::cust(Alias::new("dearmor")).arg(col).into();
    Func::cust(Alias::new("pgp_sym_decrypt"))
        .args([armored, app_encrypt_key_expr()])
        .into()
}

pub async fn update_provider_client_secret<C>(
    db: &C,
    secret: &str,
    provider_id: uuid::Uuid,
) -> Result<(), sea_orm::DbErr>
where
    C: sea_orm::ConnectionTrait,
{
    use crate::db::entity::identity_providers as ip;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    ip::Entity::update_many()
        .col_expr(ip::Column::ClientSecretEnc, pgp_encrypt_expr(secret))
        .col_expr(
            ip::Column::UpdatedAt,
            Expr::value(time::OffsetDateTime::now_utc()),
        )
        .filter(ip::Column::Id.eq(provider_id))
        .exec(db)
        .await?;
    Ok(())
}

pub async fn update_signing_key_private_key<C>(
    db: &C,
    private_key_pem: &str,
    key_id: uuid::Uuid,
) -> Result<(), sea_orm::DbErr>
where
    C: sea_orm::ConnectionTrait,
{
    use crate::db::entity::identity_provider_keys as ipk;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    ipk::Entity::update_many()
        .col_expr(
            ipk::Column::PrivateKeyPemEnc,
            pgp_encrypt_expr(private_key_pem),
        )
        .col_expr(
            ipk::Column::UpdatedAt,
            Expr::value(time::OffsetDateTime::now_utc()),
        )
        .filter(ipk::Column::Id.eq(key_id))
        .exec(db)
        .await?;
    Ok(())
}
