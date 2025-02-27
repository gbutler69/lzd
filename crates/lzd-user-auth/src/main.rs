use aes_gcm_siv::Aes256GcmSiv;
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
    let master_cipher = cipher::create(&config.master_secret)?;
    let database = lzd_db::create(&config.database).await?;
    let session_layer = SessionManagerLayer::new(MemoryStore::default());
    let backend = login::create_backend(database.clone());
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();
    let app_state = AppState {
        store: database,
        cipher: Arc::new(master_cipher),
    };
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
    cipher: Arc<Aes256GcmSiv>,
}
