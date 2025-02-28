use diesel::prelude::*;

#[derive(Identifiable, Queryable, Selectable)]
#[diesel(table_name = crate::schema::lzd::customer_type)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct CustomerType {
    pub id: i32,
    pub name: String,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
}

#[derive(Identifiable, Queryable, Selectable)]
#[diesel(table_name = crate::schema::lzd::email_type)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct EmailType {
    pub id: i32,
    pub name: String,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::lzd::email_type)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewEmailType {
    pub name: String,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
}

#[derive(Identifiable, Queryable, Selectable)]
#[diesel(table_name = crate::schema::lzd::organization_type)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct OrganizationType {
    pub id: i32,
    pub name: String,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
}

#[derive(Identifiable, Queryable, Selectable)]
#[diesel(table_name = crate::schema::lzd::phone_type)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct PhoneType {
    pub id: i32,
    pub name: String,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
}

#[derive(Identifiable, Queryable, Selectable)]
#[diesel(table_name = crate::schema::lzd::customer)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Customer {
    pub id: i32,
    pub customer_type_id: i32,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
    pub updated_by_user: i32,
}

#[derive(Identifiable, Queryable, Selectable)]
#[diesel(table_name = crate::schema::lzd::person)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Person {
    pub id: i32,
    pub encrypted_pii: Vec<u8>,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
    pub updated_by_user: i32,
}

#[derive(Identifiable, Queryable, Selectable, Associations)]
#[diesel(table_name = crate::schema::lzd::person_customer)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(Person))]
#[diesel(belongs_to(Customer))]
pub struct PersonCustomer {
    pub id: i32,
    pub customer_id: i32,
    pub person_id: i32,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
    pub updated_by_user: i32,
}

#[derive(Identifiable, Queryable, Selectable, Associations)]
#[diesel(table_name = crate::schema::lzd::person_user)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(Person))]
#[diesel(belongs_to(User))]
pub struct PersonUser {
    pub id: i32,
    pub person_id: i32,
    pub user_id: i32,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
    pub updated_by_user: i32,
}

#[derive(Identifiable, Queryable, Selectable)]
#[diesel(table_name = crate::schema::lzd::user)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: i32,
    pub logon_name: String,
    pub pass_phrase: String,
    pub secret: Vec<u8>,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::lzd::user)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewUser {
    pub logon_name: String,
    pub pass_phrase: String,
    pub secret: Vec<u8>,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
}

#[derive(Identifiable, Queryable, Selectable, Associations)]
#[diesel(table_name = crate::schema::lzd::user_email)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(User))]
pub struct UserEmail {
    pub id: i32,
    pub user_id: i32,
    pub encrypted_email_address: Vec<u8>,
    pub email_type_id: i32,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
    pub updated_by_user: i32,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::lzd::user_email)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewUserEmail {
    pub user_id: i32,
    pub encrypted_email_address: Vec<u8>,
    pub email_type_id: i32,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
    pub updated_by_user: i32,
}

#[derive(Identifiable, Queryable, Selectable, Associations)]
#[diesel(table_name = crate::schema::lzd::user_password_reset)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(primary_key(uuid))]
#[diesel(belongs_to(User))]
pub struct UserPasswordReset {
    pub uuid: uuid::Uuid,
    pub user_id: i32,
    pub created: jiff_diesel::Timestamp,
    pub updated: jiff_diesel::Timestamp,
    pub updated_by_user: i32,
}
