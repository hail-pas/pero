use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::domains::identity::helpers;
use crate::domains::identity::repos::IdentityRepo;
use crate::domains::sso::models::ChangePasswordForm;
use crate::domains::sso::routes::login::query_from_session;
use crate::domains::sso::session::{self, get_session_id};
use crate::shared::constants::identity::PROVIDER_PASSWORD;
use crate::shared::error::AppError;
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
    Form(form): Form<ChangePasswordForm>,
) -> Result<Response, AppError> {
    let (_sid, sso) = session::require(&state.cache, &headers).await?;

    if !sso.authenticated || sso.user_id.is_none() {
        return Ok(Redirect::to("/sso/login").into_response());
    }

    let user_id = sso.user_id.unwrap();
    let qp = query_from_session(&sso);

    let identity = IdentityRepo::find_by_user_and_provider(&state.db, user_id, PROVIDER_PASSWORD)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let credential = identity.credential.ok_or(AppError::Unauthorized)?;

    let valid = bcrypt::verify(&form.old_password, &credential)
        .map_err(|e| AppError::Internal(format!("Password verify error: {e}")))?;

    if !valid {
        let tpl = ChangePasswordTemplate {
            error: Some("current password is incorrect".into()),
            success: None,
            query_params: qp,
        };
        return Ok(render_tpl(&tpl)?.into_response());
    }

    if form.old_password == form.new_password {
        let tpl = ChangePasswordTemplate {
            error: Some("new password must differ from current password".into()),
            success: None,
            query_params: qp,
        };
        return Ok(render_tpl(&tpl)?.into_response());
    }

    let new_hash = helpers::hash_password(&form.new_password)?;

    let mut tx = state.db.begin().await?;
    IdentityRepo::update_credential(&mut *tx, user_id, PROVIDER_PASSWORD, &new_hash).await?;
    tx.commit().await?;

    if let Err(e) =
        crate::cache::session::revoke_refresh_token(&state.cache, &user_id.to_string()).await
    {
        tracing::warn!(error = %e, "failed to revoke refresh token after password change");
    }

    let tpl = ChangePasswordTemplate {
        error: None,
        success: Some("Password updated successfully.".into()),
        query_params: qp,
    };
    Ok(render_tpl(&tpl)?.into_response())
}
