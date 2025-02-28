use arc_swap::ArcSwap;
use diesel_async::{pooled_connection::AsyncDieselConnectionManager, AsyncPgConnection};
use std::{collections::HashMap, sync::Arc};

#[derive(Clone, Debug)]
pub struct Cache {
    pub customer_type: Arc<TypeCache<CustomerTypeName>>,
    pub email_type: Arc<TypeCache<EmailTypeName>>,
    pub organization_type: Arc<TypeCache<OrganizationTypeName>>,
    pub phone_type: Arc<TypeCache<PhoneTypeName>>,
}

impl Cache {
    pub fn new() -> Self {
        Self {
            customer_type: Arc::new(TypeCache::new()),
            email_type: Arc::new(TypeCache::new()),
            organization_type: Arc::new(TypeCache::new()),
            phone_type: Arc::new(TypeCache::new()),
        }
    }

    pub(crate) async fn populate(
        &self,
        mut conn: mobc::Connection<AsyncDieselConnectionManager<AsyncPgConnection>>,
    ) -> Result<(), Error> {
        self.customer_type
            .populate(CustomerTypeName::load_from_db(&mut conn).await?);
        self.email_type
            .populate(EmailTypeName::load_from_db(&mut conn).await?);
        self.organization_type
            .populate(OrganizationTypeName::load_from_db(&mut conn).await?);
        self.phone_type
            .populate(PhoneTypeName::load_from_db(&mut conn).await?);
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("result failure: {0}")]
    ResultError(#[from] diesel::result::Error),
    #[error("type entry does not exist")]
    DoesNotExist,
}

#[derive(Debug)]
pub struct TypeCache<T: Eq + std::hash::Hash>(ArcSwap<HashMap<T, i32>>);

impl<T: Eq + std::hash::Hash> TypeCache<T> {
    fn new() -> Self {
        Self(ArcSwap::new(Arc::new(HashMap::new())))
    }

    fn populate(&self, entries: HashMap<T, i32>) {
        self.0.swap(Arc::new(entries));
    }

    pub fn id_of(&self, name: T) -> Result<i32, Error> {
        self.0.load().get(&name).copied().ok_or(Error::DoesNotExist)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CustomerTypeName {
    Individual,
    Organization,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EmailTypeName {
    Primary,
    Home,
    Work,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OrganizationTypeName {
    Corporation,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PhoneTypeName {
    Primary,
    Home,
    Work,
    Mobile,
    Other(String),
}

macro_rules! impl_type_name {
    {
        Enum $enum_type:ty, Table $table_name:ident, Model $model_name:ident; $($variant:ident => $name:expr),+
    } => {
        impl $enum_type {
            async fn load_from_db(
                conn: &mut mobc::Connection<AsyncDieselConnectionManager<AsyncPgConnection>>,
            ) -> Result<HashMap<$enum_type, i32>, Error> {
                use super::schema::lzd::$table_name::dsl::*;
                use diesel::{QueryDsl, SelectableHelper};
                use diesel_async::RunQueryDsl;
                $table_name
                    .select(super::models::$model_name::as_select())
                    .get_results(conn)
                    .await
                    .map_err(Into::into)
                    .map(|v| {
                        v.into_iter()
                            .map(|v| (Self::from_name(&v.name), v.id))
                            .collect::<HashMap<_, _>>()
                    })
            }

            fn from_name(name: &str) -> Self {
                use $enum_type::*;
                match name {
                    $($name => $variant),+,
                    s => Self::Other(s.to_owned()),
                }
            }

            #[allow(dead_code)]
            fn to_name(&self) -> String {
                use $enum_type::*;
                match self {
                    $($variant => $name.to_owned()),+,
                    Other(s) => s.clone(),
                }
            }
        }
    };
}

impl_type_name! {
    Enum CustomerTypeName, Table customer_type, Model CustomerType;
    Individual => "Individual",
    Organization => "Organization"
}

impl_type_name! {
    Enum EmailTypeName, Table email_type, Model EmailType;
    Primary => "Primary",
    Home => "Home",
    Work => "Work"
}

impl_type_name! {
    Enum OrganizationTypeName, Table organization_type, Model OrganizationType;
    Corporation => "Corporation"
}

impl_type_name! {
    Enum PhoneTypeName, Table phone_type, Model PhoneType;
    Primary => "Primary",
    Home => "Home",
    Work => "Work",
    Mobile => "Mobile"
}
