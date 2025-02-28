use anyhow::Context;
use axum_login::{
    tower_sessions::{MemoryStore, SessionManagerLayer},
    AuthManagerLayerBuilder,
};
use std::sync::Arc;

mod cipher;
mod config;
mod login;
mod routes;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let config = config::load().context("loading configuration")?;
    let cipher = Arc::new(
        cipher::Cipher::from_base64_encoded(&config.master_secret).context("configuring cipher")?,
    );
    let store = lzd_db::create(&config.database)
        .await
        .context("creating database store")?;
    let session_layer = SessionManagerLayer::new(MemoryStore::default());
    let login_backend = login::create_backend(store.clone(), cipher.clone());
    let auth_layer = AuthManagerLayerBuilder::new(login_backend, session_layer).build();
    let app_state = AppState { store, cipher };
    let app = routes::setup(app_state, auth_layer);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .context("binding listener")?;
    Ok(axum::serve(listener, app)
        .await
        .context("serving application")?)
}

#[derive(Clone)]
struct AppState {
    store: lzd_db::Store,
    cipher: Arc<cipher::Cipher>,
}
