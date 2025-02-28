// @generated automatically by Diesel CLI.

pub mod lzd {
    diesel::table! {
        /// Contains all the Customers in the system - a given customer may have many associated persons
        lzd.customer (id) {
            id -> Int4,
            customer_type_id -> Int4,
            created -> Timestamptz,
            updated -> Timestamptz,
            updated_by_user -> Int4,
        }
    }

    diesel::table! {
        /// Contains the list of available Customer Types (e.g. Individual, Organization, etc.)
        lzd.customer_type (id) {
            id -> Int4,
            #[max_length = 128]
            name -> Varchar,
            created -> Timestamptz,
            updated -> Timestamptz,
        }
    }

    diesel::table! {
        /// Contains the list of available Email Types (e.g. Home, Work, Primary, etc.)
        lzd.email_type (id) {
            id -> Int4,
            #[max_length = 128]
            name -> Varchar,
            created -> Timestamptz,
            updated -> Timestamptz,
        }
    }

    diesel::table! {
        /// Contains the list of available Organization Types (e.g. LLC, S-Corp, Corporation, Non-Governmental Organization (NGO), etc.)
        lzd.organization_type (id) {
            id -> Int4,
            #[max_length = 128]
            name -> Varchar,
            created -> Timestamptz,
            updated -> Timestamptz,
        }
    }

    diesel::table! {
        /// Contains all the persons in the system - a given person may have man associated customers
        lzd.person (id) {
            id -> Int4,
            /// Contains an encrypted representation of all the Personally Identifiable Information of the user (e.g. Name, Date-of-Birth, etc)
            encrypted_pii -> Bytea,
            created -> Timestamptz,
            updated -> Timestamptz,
            updated_by_user -> Int4,
        }
    }

    diesel::table! {
        /// Associates persons to customers and contains any relevant data particular to that association
        lzd.person_customer (id) {
            id -> Int4,
            customer_id -> Int4,
            person_id -> Int4,
            created -> Timestamptz,
            updated -> Timestamptz,
            updated_by_user -> Int4,
        }
    }

    diesel::table! {
        /// Associates persons to users - there can be only one person per user but a person can associate to multiple users
        lzd.person_user (id) {
            id -> Int4,
            person_id -> Int4,
            user_id -> Int4,
            created -> Timestamptz,
            updated -> Timestamptz,
            updated_by_user -> Int4,
        }
    }

    diesel::table! {
        /// Contains the list of available Phone Types (e.g. Home, Work, Mobile, etc.)
        lzd.phone_type (id) {
            id -> Int4,
            #[max_length = 128]
            name -> Varchar,
            created -> Timestamptz,
            updated -> Timestamptz,
        }
    }

    diesel::table! {
        /// Contains all the users able to access the system - including service/system/admin users
        lzd.user (id) {
            id -> Int4,
            /// Contains the unencrypted logon name of the user - the user will not be able to accesss the system if they lose or forget their user logon name
            #[max_length = 64]
            logon_name -> Varchar,
            /// The pass phrase the for the user in an application managed encrypted form
            #[max_length = 1024]
            pass_phrase -> Varchar,
            secret -> Bytea,
            created -> Timestamptz,
            updated -> Timestamptz,
        }
    }

    diesel::table! {
        /// Contains the the e-mail addresses of all the users - a user can have more than one e-mail address
        lzd.user_email (id) {
            id -> Int4,
            user_id -> Int4,
            /// The email address in an application managed encrypted form for privacy - it is impossible to look-up a user by e-mail address due to this encryption
            encrypted_email_address -> Bytea,
            email_type_id -> Int4,
            created -> Timestamptz,
            updated -> Timestamptz,
            updated_by_user -> Int4,
        }
    }

    diesel::table! {
        /// Contains an entry for a user that has requested a password reset but the password has not yet been reset by the user
        lzd.user_password_reset (uuid) {
            /// The UUID corresponding to the outstanding request for password reset
            uuid -> Uuid,
            user_id -> Int4,
            created -> Timestamptz,
            updated -> Timestamptz,
            updated_by_user -> Int4,
        }
    }

    diesel::joinable!(customer -> customer_type (customer_type_id));
    diesel::joinable!(customer -> user (updated_by_user));
    diesel::joinable!(person -> user (updated_by_user));
    diesel::joinable!(person_customer -> customer (customer_id));
    diesel::joinable!(person_customer -> person (person_id));
    diesel::joinable!(person_customer -> user (updated_by_user));
    diesel::joinable!(person_user -> person (person_id));
    diesel::joinable!(user_email -> email_type (email_type_id));
    diesel::joinable!(user_email -> user (user_id));

    diesel::allow_tables_to_appear_in_same_query!(
        customer,
        customer_type,
        email_type,
        organization_type,
        person,
        person_customer,
        person_user,
        phone_type,
        user,
        user_email,
        user_password_reset,
    );
}
