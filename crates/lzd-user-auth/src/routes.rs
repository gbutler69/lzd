use super::{
    application::main,
    login::{login, logout, register_new_user, verify_email, BackEnd},
};
use axum::routing::{get, post};
use axum_login::{login_required, tower_sessions::MemoryStore, AuthManagerLayer};
use axum_messages::MessagesManagerLayer;

pub(super) fn setup(
    app_state: super::AppState,
    auth_manager: AuthManagerLayer<BackEnd, MemoryStore>,
) -> axum::routing::Router {
    axum::Router::new()
        .route("/main", get(main::get))
        .route("/verify-email/{email_id}", get(verify_email::get))
        .route("/verify-email", post(verify_email::post))
        .route_layer(login_required!(BackEnd, login_url = "/login"))
        .route("/", get(main::get))
        .route("/register", post(register_new_user::post))
        .route("/register", get(register_new_user::get))
        .route("/login", post(login::post))
        .route("/login", get(login::get))
        .route("/logout", get(logout::get))
        .layer(MessagesManagerLayer)
        .layer(auth_manager)
        .fallback(fallback)
        .with_state(app_state)
}

pub async fn fallback(_uri: axum::http::Uri) -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::NOT_FOUND, "not found")
}
