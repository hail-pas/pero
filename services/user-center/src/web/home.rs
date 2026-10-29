use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use sea_orm::EntityTrait;

use crate::db::{entity::users, enums::UserStatus};
use crate::state::app::AppState;
use crate::web::{navigation::UserLayout, session::extract_session, util};

#[derive(Debug, serde::Serialize)]
pub struct HomeView {
    pub layout: Option<UserLayout>,
}

pub async fn home(State(state): State<AppState>, jar: CookieJar) -> Response {
    let session = match extract_session(&state, &jar).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let layout = if let Some(session) = session {
        let user = match users::Entity::find_by_id(session.user_id)
            .one(&state.db)
            .await
        {
            Ok(user) => user.filter(|u| u.status == UserStatus::Active && u.deleted_at.is_none()),
            Err(error) => return util::dependency_error(error),
        };
        match user {
            Some(user) => match UserLayout::from_user(&state.db, &user).await {
                Ok(layout) => Some(layout),
                Err(error) => return util::dependency_error(error),
            },
            None => None,
        }
    } else {
        None
    };
    util::view_response("HomeView", HomeView { layout }, jar)
}
