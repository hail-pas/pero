// PERO_RUN_MODE=local ./bootstrap --config-dir config --keys-dir config/keys
use std::path::{Path, PathBuf};

use clap::Parser;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, QueryFilter, Set,
    Statement, TransactionTrait,
};
use serde::Deserialize;

use user_center::config;
use user_center::db::entity::{
    apps, identity_provider_keys, identity_providers, user_app_access, users,
};
use user_center::db::enums::{CommonStatus, IdentityProviderKind, UserStatus};
use user_center::db::init::init_db;
use user_center::service::password::PasswordIdentityService;

#[derive(Debug, Parser)]
#[command(
    name = "user-center-bootstrap",
    version,
    about = "Bootstrap user-center: create provider and admin user"
)]
struct Cli {
    #[arg(
        long,
        value_name = "DIR",
        default_value = "config",
        help = "Path to the config directory"
    )]
    config_dir: PathBuf,

    #[arg(
        long,
        value_name = "DIR",
        default_value = "config/keys",
        help = "Path to the directory containing PEM key files (public.pem, private.pem)"
    )]
    keys_dir: PathBuf,

    #[arg(
        long,
        value_name = "TASK",
        action = clap::ArgAction::Append,
        help = "Task(s) to run: provider, admin. Default: provider, admin"
    )]
    only: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BootstrapConfig {
    provider: Option<ProviderConfig>,
    admin: Option<AdminConfig>,
}

#[derive(Debug, Deserialize)]
struct ProviderConfig {
    code: String,
    name: String,
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdminConfig {
    username: String,
    password: String,
    email: Option<String>,
    phone: Option<String>,
}

fn validate_provider(p: &ProviderConfig) -> Result<(), String> {
    if p.code.trim().is_empty() {
        return Err("provider.code 不能为空".into());
    }
    if p.name.trim().is_empty() {
        return Err("provider.name 不能为空".into());
    }
    Ok(())
}

async fn run_provider(
    db: &sea_orm::DatabaseConnection,
    keys_dir: &Path,
    cfg: &ProviderConfig,
    oidc_issuer: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_provider(cfg)?;

    let existing = identity_providers::Entity::find()
        .filter(identity_providers::Column::Code.eq(&cfg.code))
        .one(db)
        .await?;

    let provider_id = if let Some(p) = existing {
        tracing::info!(code = %cfg.code, "Provider 已存在，跳过创建: {}", p.id);
        p.id
    } else {
        let now = time::OffsetDateTime::now_utc();
        let id = uuid::Uuid::now_v7();
        let provider = identity_providers::ActiveModel {
            id: Set(id),
            code: Set(cfg.code.trim().to_owned()),
            name: Set(cfg.name.trim().to_owned()),
            kind: Set(IdentityProviderKind::Local),
            issuer: Set(Some(oidc_issuer.to_owned())),
            authorization_endpoint: Set(None),
            token_endpoint: Set(None),
            userinfo_endpoint: Set(None),
            jwks_uri: Set(None),
            end_session_endpoint: Set(None),
            client_id: Set(None),
            client_secret_enc: Set(None),
            scopes: Set(vec![]),
            settings: Set(serde_json::json!({})),
            enabled: Set(true),
            created_at: Set(now),
            updated_at: Set(now),
        };
        provider.insert(db).await?;
        tracing::info!(code = %cfg.code, "✓ Provider 创建成功: {}", id);
        id
    };

    insert_signing_key(db, keys_dir, provider_id, cfg.kid.as_deref()).await?;

    Ok(())
}

async fn insert_signing_key(
    db: &sea_orm::DatabaseConnection,
    keys_dir: &Path,
    provider_id: uuid::Uuid,
    kid_override: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let existing_key = identity_provider_keys::Entity::find()
        .filter(identity_provider_keys::Column::ProviderId.eq(provider_id))
        .filter(identity_provider_keys::Column::Active.eq(true))
        .one(db)
        .await?;

    if existing_key.is_some() {
        tracing::info!("Provider 已有 active signing key，跳过");
        return Ok(());
    }

    let public_pem_path = keys_dir.join("public.pem");
    let private_pem_path = keys_dir.join("private.pem");

    if !public_pem_path.exists() || !private_pem_path.exists() {
        return Err(format!(
            "PEM 文件不存在: {} / {}\n请先运行: make gen-keys",
            public_pem_path.display(),
            private_pem_path.display()
        )
        .into());
    }

    let public_pem = std::fs::read_to_string(&public_pem_path)?;
    let private_pem = std::fs::read_to_string(&private_pem_path)?;

    let kid = kid_override
        .map(|k| k.to_owned())
        .unwrap_or_else(|| format!("key-{}", &uuid::Uuid::now_v7().to_string()[..8]));
    let kid_clone = kid.clone();
    let key_id = uuid::Uuid::now_v7();
    let now = time::OffsetDateTime::now_utc();

    let sql = format!(
        "INSERT INTO identity_provider_keys (\
            id, provider_id, kid, \"use\", algorithm,\
            public_key_pem, private_key_pem_enc,\
            active, created_at, updated_at\
        ) VALUES ($1, $2, $3, 'sig', 'RS256',\
            $4,\
            armor(pgp_sym_encrypt($5, current_setting('{}'), 'cipher-algo=aes256,compress-algo=0')),\
            true, $6, $7)",
        config::ENCRYPT_KEY_CONFIG_KEY
    );

    db.execute_raw(Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        sql,
        [
            key_id.into(),
            provider_id.into(),
            kid.into(),
            public_pem.trim().into(),
            private_pem.trim().into(),
            now.into(),
            now.into(),
        ],
    ))
    .await?;

    tracing::info!(kid = %kid_clone, "✓ Signing key 插入成功: {}", key_id);

    Ok(())
}

fn validate_admin(a: &AdminConfig) -> Result<(), String> {
    let username = a.username.trim();
    if username.len() < 3 || username.len() > 64 {
        return Err("admin.username 需要 3-64 个字符".into());
    }
    if a.password.len() < 8 {
        return Err("admin.password 至少 8 个字符".into());
    }
    if let Some(email) = &a.email
        && (!email.contains('@') || email.trim().is_empty())
    {
        return Err("admin.email 格式不正确".into());
    }
    if let Some(phone) = &a.phone {
        let phone = phone.trim();
        let digits = phone.strip_prefix('+').unwrap_or(phone);
        if phone.is_empty()
            || digits.is_empty()
            || !digits.chars().all(|c| c.is_ascii_digit())
            || digits.len() < 7
        {
            return Err("admin.phone 格式不正确".into());
        }
    }
    Ok(())
}

fn trimmed_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn admin_user_model(
    user_id: uuid::Uuid,
    cfg: &AdminConfig,
    now: time::OffsetDateTime,
) -> users::ActiveModel {
    let email = trimmed_optional(cfg.email.as_deref());
    let phone = trimmed_optional(cfg.phone.as_deref());

    users::ActiveModel {
        id: Set(user_id),
        username: Set(cfg.username.trim().to_owned()),
        email_verified_at: Set(email.as_ref().map(|_| now)),
        email: Set(email),
        phone_verified_at: Set(phone.as_ref().map(|_| now)),
        phone: Set(phone),
        nickname: Set(None),
        avatar_url: Set(None),
        status: Set(UserStatus::Active),
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
    }
}

async fn find_system_app(
    db: &sea_orm::DatabaseConnection,
) -> Result<apps::Model, Box<dyn std::error::Error>> {
    apps::Entity::find()
        .filter(apps::Column::Code.eq(config::SYSTEM_APP_CODE))
        .one(db)
        .await?
        .ok_or_else(|| {
            format!(
                "系统应用 '{}' 不存在，请先执行数据库迁移",
                config::SYSTEM_APP_CODE
            )
            .into()
        })
}

async fn run_admin(
    db: &sea_orm::DatabaseConnection,
    cfg: &AdminConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_admin(cfg)?;
    let system_app = find_system_app(db).await?;
    let txn = db.begin().await?;

    let existing = users::Entity::find()
        .filter(users::Column::Username.eq(&cfg.username))
        .one(&txn)
        .await?;

    if existing.is_some() {
        return Err(format!("用户名 '{}' 已存在", cfg.username).into());
    }

    let now = time::OffsetDateTime::now_utc();
    let user_id = uuid::Uuid::now_v7();

    let user = admin_user_model(user_id, cfg, now);
    user.insert(&txn).await?;
    tracing::info!(username = %cfg.username, "✓ 用户创建成功: {}", user_id);

    let provider = user_center::db::helper::identity_provider::find_local_provider(&txn)
        .await
        .map_err(|e| format!("未找到 local provider: {e}"))?;

    PasswordIdentityService::create(
        &txn,
        user_id,
        provider.id,
        cfg.username.trim().to_owned(),
        &cfg.password,
        now,
    )
    .await?;
    tracing::info!("✓ 密码身份创建成功");

    user_app_access::ActiveModel {
        user_id: Set(user_id),
        app_id: Set(system_app.id),
        status: Set(CommonStatus::Active),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    }
    .insert(&txn)
    .await?;

    user_center::service::security::execute(
        &txn,
        "INSERT INTO admin_roles(user_id,role) VALUES($1,'super_admin')",
        vec![user_id.into()],
    )
    .await?;
    txn.commit().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter("info")
        .init();

    let bootstrap_path = cli.config_dir.join("bootstrap.toml");
    if !bootstrap_path.exists() {
        return Err(format!(
            "Bootstrap 配置文件不存在: {}\n请参考 config/bootstrap.toml.example 创建",
            bootstrap_path.display()
        )
        .into());
    }

    let bootstrap_content = std::fs::read_to_string(&bootstrap_path)?;
    let bootstrap_cfg: BootstrapConfig = toml::from_str(&bootstrap_content)?;

    let tasks: Vec<String> = if cli.only.is_empty() {
        vec!["provider".to_owned(), "admin".to_owned()]
    } else {
        cli.only
    };

    let valid_tasks = ["provider", "admin"];
    for task in &tasks {
        if !valid_tasks.contains(&task.as_str()) {
            return Err(format!("未知任务 '{}'，可选值: {:?}", task, valid_tasks).into());
        }
    }

    tracing::info!("连接数据库...");
    let app_config = pero_config::ConfigLoader::new()
        .config_dir(&cli.config_dir)
        .load::<config::AppConfig>()?;
    let (db, _guard) = init_db(&app_config).await?;
    let oidc_issuer = app_config.oidc.issuer.clone();
    tracing::info!("数据库连接成功");

    if tasks.contains(&"provider".to_owned()) {
        tracing::info!("━━━ 创建 Provider ━━━");
        if let Some(cfg) = &bootstrap_cfg.provider {
            run_provider(&db, &cli.keys_dir, cfg, &oidc_issuer).await?;
        } else {
            tracing::warn!("bootstrap.toml 未配置 [provider]，跳过");
        }
    }

    if tasks.contains(&"admin".to_owned()) {
        tracing::info!("━━━ 创建超级管理员 ━━━");
        if let Some(cfg) = &bootstrap_cfg.admin {
            run_admin(&db, cfg).await?;
        } else {
            tracing::warn!("bootstrap.toml 未配置 [admin]，跳过");
        }
    }

    tracing::info!("━━━ 完成 ━━━");
    Ok(())
}
