use diesel::prelude::*;
use diesel_async::{RunQueryDsl, AsyncConnection, AsyncPgConnection};
use dotenvy::dotenv;
use std::env;

pub async fn establish_connection() -> AsyncPgConnection {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    AsyncPgConnection::establish(&database_url).await
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

mod email_type {
    use crate::models::{NewEmailType,EmailType};
    use crate::schema::lzd::email_type;
    use super::*;

    #[tokio::test]
    async fn it_deletes_all_then_populates_returning_the_newly_created_records() {
        let now = jiff::Timestamp::now().into();
        let new_email_types = &[
            NewEmailType{
                name: "Home".to_owned(),
                created: now,
                updated: now,
            },
            NewEmailType{
                name: "Work".to_owned(),
                created: now,
                updated: now,
            },
        ];
        let mut conn = establish_connection().await;
        diesel::delete(email_type::table).execute(&mut conn).await.expect("should delete all email_type records");
        let created_email_types = diesel::insert_into(email_type::table)
            .values(new_email_types)
            .returning(EmailType::as_returning())
            .get_results(&mut conn)
            .await
            .expect("should not error saving new records");
        assert_eq!(created_email_types.len(), 2, "should have inserted 2 records");
        assert!(created_email_types[0].id > 0, "should have been assigned an id number greater than 0");
        assert!(created_email_types[1].id > created_email_types[0].id, "second record should have been assigned an id number greater than the first record");
        assert_eq!(new_email_types[0].name, created_email_types[0].name, "name should match for records 1");
        assert_eq!(new_email_types[1].name, created_email_types[1].name, "name should match for records 2");
    }
}
