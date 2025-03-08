use crate::jobs;
use anyhow::Context;
use std::io::Read;

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub bind_address: String,
    pub bind_port: u16,
    pub master_secret: String,
    pub id_encoder_secret: String,
    pub database: lzd_db::Config,
    pub jobs: jobs::Config,
    pub tracing: TracingConfig,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TracingConfig {
    pub console: bool,
}

pub fn load() -> anyhow::Result<Config> {
    let mut configuration = String::with_capacity(4096);
    std::fs::File::open("./app-config.toml")
        .context("unable to open configuration file ./app-config.toml")?
        .read_to_string(&mut configuration)
        .context("unable to read configuratiion file ./app-config.toml")?;
    let mut config = toml::from_str::<Config>(&configuration)
        .context("unable to parse configuration file ./app-config.toml")?;
    if let Ok(smtp_user_name) = std::env::var("LZD_EMAIL_VERIFICATION_SMTP_USER_NAME") {
        config.jobs.email_verification.smtp_user_name = smtp_user_name;
    }
    if let Ok(smtp_password) = std::env::var("LZD_EMAIL_VERIFICATION_SMTP_PASSWORD") {
        config.jobs.email_verification.smtp_password = smtp_password;
    }
    Ok(config)
}
