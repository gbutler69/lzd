use askama::Template;
use scoped_futures::ScopedFutureExt;
use std::{string, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

use crate::cipher;

#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub run: bool,
    #[serde(with = "humantime_serde")]
    pub sleep: Duration,
    #[serde(with = "humantime_serde")]
    pub error_sleep: Duration,
    #[serde(with = "humantime_serde")]
    pub smtp_connect_timeout: Duration,
    pub smtp_implicit_tls: bool,
    pub smtp_user_name: String,
    pub smtp_password: String,
}

pub struct Sender {
    cipher: Arc<crate::cipher::Cipher>,
    store: lzd_db::Store,
    config: Config,
    app_host_port: String,
}

impl Sender {
    pub fn new(
        cipher: Arc<crate::cipher::Cipher>,
        store: lzd_db::Store,
        config: Config,
        app_host_port: String,
    ) -> Self {
        Self {
            cipher,
            store,
            config,
            app_host_port,
        }
    }

    #[tracing::instrument(skip(self, cancellation_token))]
    pub async fn send_verification_emails(
        &self,
        cancellation_token: CancellationToken,
    ) -> Result<SendOutcome, Error> {
        let emails_to_send = self.store.list_unverified_user_emails().await?;
        let mut send_stats = SendStatistics::new(emails_to_send.len());
        for (user, email) in emails_to_send {
            let secret = self.cipher.decrypt(&user.secret)?;
            if cancellation_token.is_cancelled() {
                return Ok(SendOutcome::Canceled(send_stats));
            }
            let email_address = String::from_utf8(
                self.cipher
                    .decrypt_with_secret(&secret, &email.encrypted_email_address)?,
            )?;
            if cancellation_token.is_cancelled() {
                return Ok(SendOutcome::Canceled(send_stats));
            }
            match self
                .record_and_send_verification_email(
                    cancellation_token.clone(),
                    &user.logon_name,
                    email.id,
                    &email_address,
                    &self.app_host_port,
                )
                .await
            {
                Ok(_) => send_stats.increment_sent(),
                Err(SendEmailError::Skipped) => send_stats.increment_skipped(),
                Err(err) => send_stats.append_error(err),
            }
            if cancellation_token.is_cancelled() {
                return Ok(SendOutcome::Canceled(send_stats));
            }
        }
        Ok(SendOutcome::Completed(send_stats))
    }

    #[tracing::instrument(skip(self, cancellation_token))]
    async fn record_and_send_verification_email(
        &self,
        cancellation_token: CancellationToken,
        logon_name: &str,
        email_id: i32,
        email_address: &str,
        app_host_port: &str,
    ) -> Result<(), SendEmailError> {
        let validation_id = rand::random_range(1111_1111..=9999_9999);
        if cancellation_token.is_cancelled() {
            return Err(SendEmailError::Cancelled);
        }
        let encoded_email_id = self.cipher.encode_id(email_id);
        if cancellation_token.is_cancelled() {
            return Err(SendEmailError::Cancelled);
        }
        match self
            .store
            .record_verification_email(email_id, validation_id, || {
                self.send_email(
                    logon_name,
                    email_address,
                    &encoded_email_id,
                    validation_id,
                    app_host_port,
                )
                .scope_boxed()
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(lzd_db::Error::Skipped) => Err(SendEmailError::Skipped),
            Err(err) => Err(SendEmailError::RecordingAndSending(err)),
        }
    }

    #[tracing::instrument(skip(self))]
    async fn send_email(
        &self,
        logon_name: &str,
        email_address: &str,
        encoded_email_id: &str,
        validation_id: i32,
        app_host_port: &str,
    ) -> Result<(), String> {
        let email = mail_builder::MessageBuilder::new()
            .subject("Account Email Confirmation")
            .from("gerald.edward.butler@gmail.com")
            .sender("gerald.edward.butler@gmail.com")
            .to(email_address)
            .html_body(
                EmailHtmlTemplate {
                    user_name: logon_name,
                    encoded_email_id,
                    validation_id,
                    app_host_port,
                }
                .render()
                .map_err(|err| format!("Template Error: {err:?}"))?,
            )
            .text_body(
                EmailTextTemplate {
                    user_name: logon_name,
                    encoded_email_id,
                    validation_id,
                    app_host_port,
                }
                .render()
                .map_err(|err| format!("Template Error: {err:?}"))?,
            );
        mail_send::SmtpClientBuilder::new("smtp.gmail.com", 587)
            .implicit_tls(self.config.smtp_implicit_tls)
            .credentials((
                self.config.smtp_user_name.as_str(),
                self.config.smtp_password.as_str(),
            ))
            .timeout(self.config.smtp_connect_timeout)
            .connect()
            .await
            .map_err(|err| format!("Connecting to SMTP Server: {err:?}"))?
            .send(email)
            .await
            .map_err(|err| format!("Sending Email: {err:?}"))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("User database error: {0}")]
    UserDb(#[from] lzd_db::Error),
    #[error("Failed Encryption/Decryption: {0}")]
    EncryptionDecryption(#[from] crate::cipher::Error),
    #[error("Converting to String: {0}")]
    ConversionToString(#[from] string::FromUtf8Error),
}

pub enum SendOutcome {
    Completed(SendStatistics),
    Canceled(SendStatistics),
}

#[derive(Debug)]
pub struct SendStatistics {
    pub(super) sent: usize,
    pub(super) skipped: usize,
    pub(super) remaining: usize,
    pub(super) errors: Vec<SendEmailError>,
}

impl SendStatistics {
    fn new(count: usize) -> Self {
        Self {
            sent: 0,
            skipped: 0,
            remaining: count,
            errors: Vec::new(),
        }
    }

    fn increment_sent(&mut self) {
        self.sent += 1;
        self.remaining -= 1;
    }

    fn increment_skipped(&mut self) {
        self.skipped += 1;
        self.remaining -= 1;
    }

    fn append_error(&mut self, error: SendEmailError) {
        self.remaining -= 1;
        self.errors.push(error);
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SendEmailError {
    #[error("Cancelled")]
    Cancelled,
    #[error("Cipher: {0}")]
    CipherError(#[from] cipher::Error),
    #[error("Skipped")]
    Skipped,
    #[error("Recording and Sending: {0}")]
    RecordingAndSending(lzd_db::Error),
}

#[derive(Template)]
#[template(path = "email/verification.txt")]
pub struct EmailTextTemplate<'a> {
    user_name: &'a str,
    encoded_email_id: &'a str,
    validation_id: i32,
    app_host_port: &'a str,
}

#[derive(Template)]
#[template(path = "email/verification.html")]
pub struct EmailHtmlTemplate<'a> {
    user_name: &'a str,
    encoded_email_id: &'a str,
    validation_id: i32,
    app_host_port: &'a str,
}
