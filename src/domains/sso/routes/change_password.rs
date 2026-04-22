use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::domains::identity::auth_service::AuthService;
use crate::domains::sso::models::ChangePasswordForm;
use crate::domains::sso::routes::login::query_from_session;
use crate::domains::sso::session::{self, get_session_id};
use crate::shared::error::AppError;
use crate::shared::extractors::ValidatedForm;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "sso/change_password.html")]
pub struct ChangePasswordTemplate {
    pub error: Option<String>,
    pub success: Option<String>,
    pub query_params: String,
}

fn render_tpl(tpl: &ChangePasswordTemplate) -> Result<Html<String>, AppError> {
    tpl.render()
        .map(Html)
        .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn change_password_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let sid = get_session_id(&headers);
    match sid {
        Some(sid) => {
            let sso = session::get(&state.cache, &sid).await?;
            match sso {
                Some(sso) => {
                    if !sso.authenticated || sso.user_id.is_none() {
                        return Ok(Redirect::to("/sso/login").into_response());
                    }
                    let qp = query_from_session(&sso);
                    let tpl = ChangePasswordTemplate {
                        error: None,
                        success: None,
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

pub async fn change_password_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(form): ValidatedForm<ChangePasswordForm>,
) -> Result<Response, AppError> {
    let (_sid, sso) = session::require(&state.cache, &headers).await?;

    if !sso.authenticated || sso.user_id.is_none() {
        return Ok(Redirect::to("/sso/login").into_response());
    }

    let user_id = sso.user_id.unwrap();
    let qp = query_from_session(&sso);
    if let Err(err) =
        AuthService::change_password(&state, user_id, &form.old_password, &form.new_password).await
    {
        let message = match err {
            AppError::BadRequest(message) => message,
            AppError::Unauthorized => "invalid credentials".to_string(),
            other => return Err(other),
        };
        let tpl = ChangePasswordTemplate {
            error: Some(message),
            success: None,
            query_params: qp,
        };
        return Ok(render_tpl(&tpl)?.into_response());
    }

    let tpl = ChangePasswordTemplate {
        error: None,
        success: Some("Password updated successfully.".into()),
        query_params: qp,
    };
    Ok(render_tpl(&tpl)?.into_response())
}
