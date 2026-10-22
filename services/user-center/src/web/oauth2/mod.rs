pub mod authorize;
pub mod end_session;

use axum::routing::get;

pub fn routes() -> axum::Router<crate::state::app::AppState> {
    axum::Router::new()
        .route("/oauth2/authorize", get(authorize::authorize))
        .route("/oauth2/authorize/resume", get(authorize::resume))
        .route(
            "/oauth2/session/end",
            get(end_session::end_session).post(end_session::end_session_post),
        )
}
