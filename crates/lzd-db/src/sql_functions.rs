use diesel::define_sql_function;

define_sql_function!(fn lower(a: diesel::sql_types::VarChar) -> diesel::sql_types::VarChar);
