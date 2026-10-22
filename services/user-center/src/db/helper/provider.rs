use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, FromQueryResult, QueryFilter, QuerySelect,
    sea_query::Expr,
};

use crate::db::crypto_expr::pgp_decrypt_expr;
use crate::db::entity::identity_providers as ip;
use crate::db::enums::IdentityProviderKind;

#[derive(Clone, FromQueryResult)]
pub struct ProviderWithSecret {
    #[sea_orm(nested)]
    pub provider: ip::Model,

    #[sea_orm(from_alias = "client_secret")]
    pub client_secret: Option<String>,
}

pub async fn find_provider_with_secret<C>(
    db: &C,
    provider_id: uuid::Uuid,
) -> Result<Option<ProviderWithSecret>, DbErr>
where
    C: ConnectionTrait,
{
    ip::Entity::find()
        .expr_as(
            pgp_decrypt_expr(Expr::col(ip::Column::ClientSecretEnc)),
            "client_secret",
        )
        .filter(ip::Column::Id.eq(provider_id))
        .filter(ip::Column::Kind.is_in([
            IdentityProviderKind::Oauth2,
            IdentityProviderKind::Oidc,
            IdentityProviderKind::Wechat,
        ]))
        .filter(ip::Column::Enabled.eq(true))
        .into_model::<ProviderWithSecret>()
        .one(db)
        .await
}
