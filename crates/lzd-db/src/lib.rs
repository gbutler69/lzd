use diesel::prelude::*;
use diesel_async::{
    pooled_connection::{
        mobc::{Builder, Pool},
        AsyncDieselConnectionManager,
    },
    scoped_futures::ScopedFutureExt,
    AsyncConnection, AsyncPgConnection, RunQueryDsl,
};
use std::time::Duration;

pub mod models;
mod schema;
#[cfg(test)]
mod tests;
mod types_cache;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("getting connection from pool: {0}")]
    GetConnectionPool(#[from] mobc::Error<diesel_async::pooled_connection::PoolError>),
    #[error("result failure: {0}")]
    Result(#[from] diesel::result::Error),
    #[error("type cache: {0}")]
    TypeCache(#[from] types_cache::Error),
}

#[derive(Clone, Debug)]
pub struct Store {
    pool: Pool<AsyncPgConnection>,
    types_cache: types_cache::Cache,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    db_url: String,
    max_open: u64,
    max_idle: u64,
    #[serde(with = "humantime_serde", default)]
    max_lifetime: Option<Duration>,
    #[serde(with = "humantime_serde", default)]
    max_idle_lifetime: Option<Duration>,
    #[serde(with = "humantime_serde")]
    timeout_for_get: Duration,
}

pub async fn create(config: &Config) -> Result<Store, Error> {
    let pool = create_pool(config);
    let types_cache = create_types_cache(pool.clone()).await?;
    Ok(Store { pool, types_cache })
}

fn create_pool(config: &Config) -> mobc::Pool<AsyncDieselConnectionManager<AsyncPgConnection>> {
    let builder = Builder::new()
        .max_open(config.max_open)
        .max_idle(config.max_idle)
        .max_lifetime(
            config
                .max_lifetime
                .map(|v| v.max(Duration::from_secs(3600))),
        )
        .max_idle_lifetime(
            config
                .max_idle_lifetime
                .map(|v| v.max(Duration::from_secs(900))),
        )
        .get_timeout(Some(config.timeout_for_get.max(Duration::from_secs(5))));
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&config.db_url);
    let pool = builder.build(manager);
    pool
}

async fn create_types_cache(
    pool: mobc::Pool<AsyncDieselConnectionManager<AsyncPgConnection>>,
) -> Result<types_cache::Cache, Error> {
    let conn = pool.get().await?;
    let cache = types_cache::Cache::new();
    cache.populate(conn).await?;
    Ok(cache)
}

impl Store {
    async fn connection(
        &self,
    ) -> Result<mobc::Connection<AsyncDieselConnectionManager<AsyncPgConnection>>, Error> {
        self.pool.get().await.map_err(Into::into)
    }

    pub async fn load_user_by_logon_name(&self, name: &str) -> Result<Option<models::User>, Error> {
        use schema::lzd::user::dsl::*;
        let mut conn = self.connection().await?;
        match user
            .filter(logon_name.eq(name))
            .select(models::User::as_select())
            .first(&mut conn)
            .await
        {
            Ok(loaded_user) => Ok(Some(loaded_user)),
            Err(diesel::result::Error::NotFound) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn load_user_by_id(&self, user_id: i32) -> Result<Option<models::User>, Error> {
        use schema::lzd::user::dsl::*;
        let mut conn = self.connection().await?;
        match user
            .filter(id.eq(user_id))
            .select(models::User::as_select())
            .first(&mut conn)
            .await
        {
            Ok(loaded_user) => Ok(Some(loaded_user)),
            Err(diesel::result::Error::NotFound) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn register_user(
        &self,
        user_name: String,
        hashed_pass_phrase: String,
        encrypted_email_address: Vec<u8>,
        encrypted_secret: Vec<u8>,
    ) -> Result<(models::User, models::UserEmail), Error> {
        let now = jiff::Timestamp::now().into();
        let new_user = models::NewUser {
            logon_name: user_name,
            pass_phrase: hashed_pass_phrase,
            secret: encrypted_secret,
            created: now,
            updated: now,
        };
        self.connection()
            .await?
            .transaction(|mut conn| {
                use schema::lzd::{user, user_email};
                async move {
                    let new_user = match diesel::insert_into(user::table)
                        .values(new_user)
                        .returning(models::User::as_returning())
                        .get_result(&mut conn)
                        .await
                    {
                        Ok(new_user) => new_user,
                        Err(err) => Err(err)?,
                    };
                    let new_user_email = models::NewUserEmail {
                        user_id: new_user.id,
                        encrypted_email_address,
                        email_type_id: self
                            .types_cache
                            .email_type
                            .id_of(types_cache::EmailTypeName::Primary)?,
                        created: now,
                        updated: now,
                        updated_by_user: new_user.id,
                    };
                    let new_user_email = match diesel::insert_into(user_email::table)
                        .values(new_user_email)
                        .returning(models::UserEmail::as_returning())
                        .get_result(&mut conn)
                        .await
                    {
                        Ok(new_user_email) => new_user_email,
                        Err(err) => Err(err)?,
                    };
                    Ok::<_, Error>((new_user, new_user_email))
                }
                .scope_boxed()
            })
            .await
            .map_err(Into::into)
    }
}
