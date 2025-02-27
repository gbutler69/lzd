use anyhow::Context;
use std::io::Read;

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub master_secret: String,
    pub database: lzd_db::Config,
}

pub fn load() -> anyhow::Result<Config> {
    let mut configuration = String::with_capacity(1024);
    std::fs::File::open("./app-config.toml")
        .context("unable to open configuration file ./app-config.toml")?
        .read_to_string(&mut configuration)
        .context("unable to read configuratiion file ./app-config.toml")?;
    toml::from_str(&configuration).context("unable to parse configuration file ./app-config.toml")
}
