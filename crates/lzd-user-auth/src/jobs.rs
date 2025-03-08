use std::sync::Arc;
use tokio_util::sync::CancellationToken;

mod email_verification;

pub fn create(
    config: Config,
    cipher: Arc<crate::cipher::Cipher>,
    store: lzd_db::Store,
    app_host_port: String,
) -> Jobs {
    Jobs {
        config: Arc::new(config),
        cipher,
        store,
        app_host_port,
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("User database error: {0}")]
    EmailVerifier(#[from] email_verification::Error),
}

pub struct Jobs {
    config: Arc<Config>,
    cipher: Arc<crate::cipher::Cipher>,
    store: lzd_db::Store,
    app_host_port: String,
}

impl Jobs {
    pub async fn run(&self, cancellation_token: CancellationToken) -> Result<(), Error> {
        self.run_email_verifier(cancellation_token).await
    }

    #[tracing::instrument(skip(self, cancellation_token))]
    async fn run_email_verifier(&self, cancellation_token: CancellationToken) -> Result<(), Error> {
        use email_verification::*;
        use tokio::time::sleep;
        let email_verifier = email_verification::Sender::new(
            self.cipher.clone(),
            self.store.clone(),
            self.config.email_verification.clone(),
            self.app_host_port.clone(),
        );
        loop {
            if self.config.email_verification.run {
                match email_verifier
                    .send_verification_emails(cancellation_token.clone())
                    .await
                {
                    Ok(SendOutcome::Completed(stats)) => {
                        tracing::info!("Send Email Statistics: {stats:?}");
                        if !stats.errors.is_empty() && stats.sent == 0 {
                            tokio::select! {
                                _ = cancellation_token.cancelled() => (),
                                _ = sleep(self.config.email_verification.error_sleep) => ()
                            }
                        } else if stats.sent == 0 {
                            tokio::select! {
                                _ = cancellation_token.cancelled() => (),
                                _ = sleep(self.config.email_verification.sleep) => ()
                            }
                        }
                    }
                    Ok(SendOutcome::Canceled(stats)) => {
                        tracing::info!("Send Email Statistics: {stats:?}");
                        break;
                    }
                    Err(err) => {
                        tracing::error!("Send Email Error: {err:?}");
                        tokio::select! {
                            _ = cancellation_token.cancelled() => (),
                            _ = sleep(self.config.email_verification.error_sleep) => ()
                        }
                    }
                }
                if cancellation_token.is_cancelled() {
                    break;
                }
            } else {
                tokio::select! {
                    _ = cancellation_token.cancelled() => (),
                    _ = sleep(self.config.email_verification.error_sleep) => ()
                }
                if cancellation_token.is_cancelled() {
                    break;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub email_verification: email_verification::Config,
}
