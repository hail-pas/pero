use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::domains::identity::helpers;
use crate::domains::identity::repos::{IdentityRepo, UserRepo};
use crate::domains::sso::models::RegisterForm;
use crate::domains::sso::routes::login::query_from_session;
use crate::domains::sso::session::{self, get_session_id};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "sso/register.html")]
pub struct RegisterTemplate {
    pub client_name: Option<String>,
    pub username: String,
    pub email: String,
    pub nickname: String,
    pub phone: String,
    pub error: Option<String>,
    pub query_params: String,
}

fn render_tpl(tpl: &RegisterTemplate) -> Result<Html<String>, AppError> {
    tpl.render()
        .map(Html)
        .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn register_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let sid = get_session_id(&headers);
    match sid {
        Some(sid) => {
            let sso = session::get(&state.cache, &sid).await?;
            match sso {
                Some(sso) => {
                    let qp = query_from_session(&sso);
                    let tpl = RegisterTemplate {
                        client_name: None,
                        username: String::new(),
                        email: String::new(),
                        nickname: String::new(),
                        phone: String::new(),
                        error: None,
                        query_params: qp,
                    };
                    Ok(render_tpl(&tpl)?.into_response())
                }
                None => Ok(Redirect::to("/oauth2/authorize").into_response()),
            }
        }
        None => Ok(Redirect::to("/oauth2/authorize").into_response()),
    }
}

pub async fn register_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Result<Response, AppError> {
    let (sid, mut sso) = session::require(&state.cache, &headers).await?;
    let qp = query_from_session(&sso);

    if UserRepo::find_by_username(&state.db, &form.username)
        .await?
        .is_some()
    {
        let tpl = RegisterTemplate {
            client_name: None,
            username: form.username.clone(),
            email: form.email.clone(),
            nickname: form.nickname.clone().unwrap_or_default(),
            phone: form.phone.clone().unwrap_or_default(),
            error: Some("username already exists".into()),
            query_params: qp,
        };
        return Ok(render_tpl(&tpl)?.into_response());
    }
    if UserRepo::find_by_email(&state.db, &form.email)
        .await?
        .is_some()
    {
        let tpl = RegisterTemplate {
            client_name: None,
            username: form.username.clone(),
            email: form.email.clone(),
            nickname: form.nickname.clone().unwrap_or_default(),
            phone: form.phone.clone().unwrap_or_default(),
            error: Some("email already exists".into()),
            query_params: qp.clone(),
        };
        return Ok(render_tpl(&tpl)?.into_response());
    }
    if let Some(phone) = &form.phone {
        if UserRepo::find_by_phone(&state.db, phone).await?.is_some() {
            let tpl = RegisterTemplate {
                client_name: None,
                username: form.username.clone(),
                email: form.email.clone(),
                nickname: form.nickname.clone().unwrap_or_default(),
                phone: form.phone.clone().unwrap_or_default(),
                error: Some("phone already exists".into()),
                query_params: qp,
            };
            return Ok(render_tpl(&tpl)?.into_response());
        }
    }

    let password_hash = helpers::hash_password(&form.password)?;

    let mut tx = state.db.begin().await?;

    let user = UserRepo::create(
        &mut *tx,
        &form.username,
        &form.email,
        form.phone.as_deref(),
        form.nickname.as_deref(),
    )
    .await?;

    IdentityRepo::create_password(&mut *tx, user.id, &password_hash).await?;

    tx.commit().await?;

    sso.user_id = Some(user.id);
    sso.authenticated = true;
    sso.auth_time = Some(chrono::Utc::now().timestamp());
    session::update(&state.cache, &sid, &sso).await?;

    Ok(Redirect::to("/sso/consent").into_response())
}
