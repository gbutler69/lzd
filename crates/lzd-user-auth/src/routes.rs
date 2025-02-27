use super::login::{login, logout, register_new_user, BackEnd};
use axum::routing::{get, post};
use axum_login::{login_required, tower_sessions::MemoryStore, AuthManagerLayer};
use axum_messages::MessagesManagerLayer;

pub(super) fn setup(
    app_state: super::AppState,
    auth_manager: AuthManagerLayer<BackEnd, MemoryStore>,
) -> axum::routing::Router {
    axum::Router::new()
        .route("/hello-logged-in", get(hello_logged_in))
        .route_layer(login_required!(BackEnd, login_url = "/login"))
        .route("/login", post(login::post))
        .route("/login", get(login::get))
        .route("/", get(hello))
        .route("/logout", post(logout::post))
        .route("/logout", get(logout::get))
        .route("/register", post(register_new_user::post))
        .route("/register", get(register_new_user::get))
        .layer(MessagesManagerLayer)
        .layer(auth_manager)
        .fallback(fallback)
        .with_state(app_state)
}

pub async fn hello() -> &'static str {
    "HELLO"
}

pub async fn hello_logged_in() -> &'static str {
    "HELLO AGAIN"
}

pub async fn fallback(_uri: axum::http::Uri) -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::NOT_FOUND, "not found")
}
