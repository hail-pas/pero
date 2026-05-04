use pero::config::AppConfig;
use pero::domain::credential::entity::Identity;
use pero::domain::user::entity::User;
use std::io::{self, Write};

fn prompt(label: &str) -> String {
    print!("{}: ", label);
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    buf.trim().to_string()
}

fn prompt_default(label: &str, default: &str) -> String {
    print!("{} [{}]: ", label, default);
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    let v = buf.trim().to_string();
    if v.is_empty() { default.to_string() } else { v }
}

fn prompt_password(label: &str) -> String {
    print!("{}: ", label);
    io::stdout().flush().unwrap();
    let password = rpassword::read_password().unwrap_or_else(|_| {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).unwrap();
        buf.trim().to_string()
    });
    password.trim().to_string()
}

fn confirm(label: &str) -> bool {
    let answer = prompt(&format!("{} (y/N)", label));
    answer == "y" || answer == "Y"
}

fn print_header(title: &str) {
    println!();
    println!("=== {} ===", title);
    println!();
}

fn print_step(n: usize, title: &str) {
    println!();
    println!("--- Step {}: {} ---", n, title);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapMode {
    Both,
    UserOnly,
    AppOnly,
}

fn select_mode() -> BootstrapMode {
    println!("Select what to create:");
    println!("  1. Super admin + OAuth2 client (default)");
    println!("  2. Super admin only");
    println!("  3. OAuth2 client only");
    println!();
    let answer = prompt_default("Choice", "1");
    match answer.as_str() {
        "2" => BootstrapMode::UserOnly,
        "3" => BootstrapMode::AppOnly,
        _ => BootstrapMode::Both,
    }
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cfg = AppConfig::load().expect("Failed to load configuration");
    pero::infra::logging::init(&cfg.log);

    let pool = pero::infra::db::init_pool(&cfg.database)
        .await
        .expect("Failed to connect to database");

    print_header("Pero Bootstrap");

    let mode = select_mode();

    println!();
    println!(
        "Will create: {}",
        match mode {
            BootstrapMode::Both => "Super admin + OAuth2 client",
            BootstrapMode::UserOnly => "Super admin only",
            BootstrapMode::AppOnly => "OAuth2 client only",
        }
    );

    if !confirm("Continue?") {
        println!("Aborted.");
        return;
    }

    let mut step = 0;

    if mode == BootstrapMode::Both || mode == BootstrapMode::UserOnly {
        step += 1;
        print_step(step, "Create Super Admin");

        let username = loop {
            let v = prompt("Username (3-64 chars)");
            if v.len() >= 3 && v.len() <= 64 {
                match sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
                    .bind(&v)
                    .fetch_optional(&pool)
                    .await
                {
                    Ok(None) => break v,
                    Ok(Some(_)) => println!("  ! Username '{}' already exists, try another", v),
                    Err(e) => {
                        eprintln!("  ! Database error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                println!("  ! Must be 3-64 characters");
            }
        };

        let email = loop {
            let v = prompt_default("Email (leave empty to skip)", "");
            if v.is_empty() {
                break None;
            }
            if v.contains('@') && v.contains('.') {
                match sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
                    .bind(&v)
                    .fetch_optional(&pool)
                    .await
                {
                    Ok(None) => break Some(v),
                    Ok(Some(_)) => println!("  ! Email '{}' already exists, try another", v),
                    Err(e) => {
                        eprintln!("  ! Database error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                println!("  ! Invalid email format");
            }
        };

        let phone = loop {
            let v = prompt_default("Phone (leave empty to skip)", "");
            if v.is_empty() {
                break None;
            }
            match sqlx::query_as::<_, User>("SELECT * FROM users WHERE phone = $1")
                .bind(&v)
                .fetch_optional(&pool)
                .await
            {
                Ok(None) => break Some(v),
                Ok(Some(_)) => println!("  ! Phone '{}' already exists, try another", v),
                Err(e) => {
                    eprintln!("  ! Database error: {}", e);
                    std::process::exit(1);
                }
            }
        };

        let password = loop {
            let v = prompt_password("Password (8+ chars)");
            if v.len() >= 8 {
                break v;
            } else {
                println!("  ! Must be at least 8 characters");
            }
        };

        let nickname = prompt_default("Nickname", "Super Admin");

        println!();
        println!("  Username: {}", username);
        println!("  Email:    {}", email.as_deref().unwrap_or("(none)"));
        println!("  Phone:    {}", phone.as_deref().unwrap_or("(none)"));
        println!("  Nickname: {}", nickname);

        if !confirm("Create this admin user?") {
            println!("Skipped.");
        } else {
            let password_hash =
                pero::shared::crypto::hash_secret(&password).expect("Failed to hash password");
            let mut tx = pool.begin().await.expect("Failed to begin transaction");

            let user = sqlx::query_as::<_, User>(
                "INSERT INTO users (username, email, phone, nickname) VALUES ($1, $2, $3, $4) RETURNING *",
            )
            .bind(&username)
            .bind(email.as_deref())
            .bind(phone.as_deref())
            .bind(Some(&nickname))
            .fetch_one(&mut *tx)
            .await
            .expect("Failed to create user");

            sqlx::query_as::<_, Identity>(
                "INSERT INTO identities (user_id, provider, provider_uid, credential, verified) VALUES ($1, 'password', $1, $2, true) RETURNING *",
            )
            .bind(user.id)
            .bind(&password_hash)
            .fetch_one(&mut *tx)
            .await
            .expect("Failed to create password identity");

            let policy_name = format!("super-admin-{}", user.id);
            let policy_id: uuid::Uuid = sqlx::query_scalar(
                "INSERT INTO policies (name, description, effect, priority, enabled) VALUES ($1, $2, 'allow', 999, true) RETURNING id"
            )
            .bind(&policy_name)
            .bind("Full access for super admin")
            .fetch_one(&mut *tx)
            .await
            .expect("Failed to create policy");

            for (condition_type, key, operator, value) in [
                ("resource", "id", "wildcard", "/api/**"),
                ("action", "id", "in", "get,post,put,delete"),
            ] {
                sqlx::query(
                    "INSERT INTO policy_conditions (policy_id, condition_type, key, operator, value) VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(policy_id)
                .bind(condition_type)
                .bind(key)
                .bind(operator)
                .bind(value)
                .execute(&mut *tx)
                .await
                .expect("Failed to create policy condition");
            }

            sqlx::query("INSERT INTO user_policies (user_id, policy_id) VALUES ($1, $2)")
                .bind(user.id)
                .bind(policy_id)
                .execute(&mut *tx)
                .await
                .expect("Failed to assign policy");

            tx.commit().await.expect("Failed to commit transaction");

            println!("  Done! User ID: {}", user.id);
        }
    }

    if mode == BootstrapMode::Both || mode == BootstrapMode::AppOnly {
        step += 1;
        print_step(step, "Create OAuth2 Client");

        let client_name = prompt_default("Client name", "Example App");
        let redirect_uri = prompt_default("Redirect URI", "http://localhost:9000/callback");
        let post_logout_default = redirect_uri
            .rsplit_once('/')
            .map(|(base, _)| format!("{}/", base))
            .unwrap_or_else(|| format!("{}/", redirect_uri));
        let post_logout_uri = prompt_default("Post Logout Redirect URI", &post_logout_default);

        println!();
        println!("  Client name:           {}", client_name);
        println!("  Redirect URI:          {}", redirect_uri);
        println!("  Post Logout Redirect:  {}", post_logout_uri);

        if !confirm("Create this OAuth2 client?") {
            println!("Skipped.");
        } else {
            let code: String = client_name
                .to_lowercase()
                .chars()
                .map(|c| {
                    if c.is_ascii_lowercase() || c.is_ascii_digit() {
                        c
                    } else {
                        '-'
                    }
                })
                .collect();
            let app = sqlx::query_as::<_, pero::domain::app::entity::App>(
                "INSERT INTO apps (name, code, description) VALUES ($1, $2, $3) RETURNING *",
            )
            .bind(&client_name)
            .bind(&code)
            .bind(None::<&str>)
            .fetch_one(&pool)
            .await
            .expect("Failed to create app");

            let client_id_str = uuid::Uuid::new_v4().to_string().replace('-', "");
            let client_secret = uuid::Uuid::new_v4().to_string().replace('-', "");
            let client_secret_hash = pero::shared::crypto::hash_secret(&client_secret)
                .expect("Failed to hash client secret");

            let client = sqlx::query_as::<_, pero::domain::oauth::entity::OAuth2Client>(
                "INSERT INTO oauth2_clients (app_id, client_id, client_secret_hash, client_name, redirect_uris, grant_types, scopes, post_logout_redirect_uris) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
            )
            .bind(app.id)
            .bind(&client_id_str)
            .bind(&client_secret_hash)
            .bind(&client_name)
            .bind(vec![redirect_uri.clone()])
            .bind(vec!["authorization_code".to_string()])
            .bind(vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ])
            .bind(vec![post_logout_uri.clone()])
            .fetch_one(&pool)
            .await
            .expect("Failed to create OAuth2 client");

            println!("  Done!");
            println!();
            println!("  Client ID:     {}", client.client_id);
            println!("  Client Secret: {}", client_secret);
            println!("  Redirect URI:          {}", redirect_uri);
            println!("  Post Logout Redirect:  {}", post_logout_uri);
            println!("  Scopes:                openid, profile, email");
        }
    }

    print_header("Bootstrap Complete");
}
