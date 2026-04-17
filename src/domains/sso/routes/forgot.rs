use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::domains::identity::repos::UserRepo;
use crate::domains::sso::models::ForgotPasswordForm;
use crate::domains::sso::routes::login::query_from_session;
use crate::domains::sso::session::{self, get_session_id};
use crate::shared::constants::cache_keys::PASSWORD_RESET_PREFIX;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

const PASSWORD_RESET_TTL_SECONDS: i64 = 900;

#[derive(Template, Debug)]
#[template(path = "sso/forgot.html")]
pub struct ForgotTemplate {
    pub email: String,
    pub success: Option<String>,
    pub error: Option<String>,
    pub query_params: String,
}

fn render_tpl(tpl: &ForgotTemplate) -> Result<Html<String>, AppError> {
    tpl.render()
        .map(Html)
        .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn forgot_get(
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
                    let tpl = ForgotTemplate {
                        email: String::new(),
                        success: None,
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

pub async fn forgot_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ForgotPasswordForm>,
) -> Result<Response, AppError> {
    let (_sid, sso) = session::require(&state.cache, &headers).await?;
    let qp = query_from_session(&sso);

    if let Some(user) = UserRepo::find_by_email(&state.db, &form.email).await? {
        let token = uuid::Uuid::new_v4().to_string().replace('-', "");
        let key = format!("{}{}", PASSWORD_RESET_PREFIX, token);
        crate::cache::set(
            &state.cache,
            &key,
            &user.id.to_string(),
            PASSWORD_RESET_TTL_SECONDS,
        )
        .await?;
        tracing::info!(
            user_id = %user.id,
            token = %token,
            "password reset token generated"
        );
    }

    let tpl = ForgotTemplate {
        email: form.email,
        success: Some("If an account with that email exists, a reset link has been sent.".into()),
        error: None,
        query_params: qp,
    };
    Ok(render_tpl(&tpl)?.into_response())
}
