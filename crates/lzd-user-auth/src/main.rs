use anyhow::Context;
use axum_login::{
    tower_sessions::{MemoryStore, SessionManagerLayer},
    AuthManagerLayerBuilder,
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

mod application;
mod cipher;
mod config;
mod jobs;
mod login;
mod routes;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv()?;
    let cancellation_token = CancellationToken::new();
    let config = config::load().context("loading configuration")?;
    setup_tracing(&config.tracing)?;
    let cipher = Arc::new(
        cipher::Cipher::from_base64_encoded_secrets(
            &config.master_secret,
            &config.id_encoder_secret,
        )
        .context("configuring cipher")?,
    );
    let store = lzd_db::create(&config.database)
        .await
        .context("creating database store")?;
    let background_jobs = tokio::spawn(create_and_run_background_jobs(
        config.jobs.clone(),
        cipher.clone(),
        store.clone(),
        format!("{}:{}", config.bind_address, config.bind_port),
        cancellation_token.clone(),
    ));
    let web_server = tokio::spawn(create_and_start_web_server(
        config.bind_address.clone(),
        config.bind_port,
        cipher,
        store,
        cancellation_token,
    ));
    let (web_server, background_jobs) = tokio::join!(web_server, background_jobs);
    web_server??;
    Ok(background_jobs??)
}

fn setup_tracing(config: &config::TracingConfig) -> anyhow::Result<()> {
    use tracing_subscriber::fmt::format::FmtSpan;
    if config.console {
        console_subscriber::init();
    } else {
        let subscriber_builder = tracing_subscriber::fmt()
            .with_ansi(true)
            .with_level(true)
            .with_span_events(FmtSpan::FULL)
            .with_file(true)
            .with_line_number(true)
            .with_thread_ids(true)
            .with_target(true);
        let subscriber = subscriber_builder.finish();
        tracing::subscriber::set_global_default(subscriber)?;
    };
    Ok(())
}

async fn create_and_start_web_server(
    bind_address: String,
    bind_port: u16,
    cipher: Arc<cipher::Cipher>,
    store: lzd_db::Store,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    let router = routes::setup(
        AppState {
            store: store.clone(),
            cipher: cipher.clone(),
        },
        AuthManagerLayerBuilder::new(
            login::create_backend(store, cipher),
            SessionManagerLayer::new(MemoryStore::default()),
        )
        .build(),
    );
    let listener = tokio::net::TcpListener::bind(format!("{bind_address}:{bind_port}"))
        .await
        .context("binding listener")?;
    Ok(axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(cancellation_token))
        .await
        .context("serving application")?)
}

async fn shutdown_signal(cancellation_token: CancellationToken) {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            cancellation_token.cancel();
        },
        _ = terminate => {
            cancellation_token.cancel();
        },
    }
}

async fn create_and_run_background_jobs(
    config: jobs::Config,
    cipher: Arc<cipher::Cipher>,
    store: lzd_db::Store,
    app_host_port: String,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    let jobs = jobs::create(config, cipher, store, app_host_port);
    Ok(jobs.run(cancellation_token).await?)
}

#[derive(Clone)]
struct AppState {
    store: lzd_db::Store,
    cipher: Arc<cipher::Cipher>,
}
