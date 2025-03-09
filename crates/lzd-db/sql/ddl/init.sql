--
-- lzd."__diesel_schema_migrations" definition
--

create table if not exists  lzd."__diesel_schema_migrations" (
	"version" varchar(50) not null,
	run_on timestamp default CURRENT_TIMESTAMP not null,
	constraint "__diesel_schema_migrations_pkey" primary key (version)
);


--
-- Type Tables
--

create table if not exists lzd.customer_type (
	id serial primary key,
	name varchar(128) not null unique,
	created timestamp with time zone not null,
	updated timestamp with time zone not null
);

comment on table lzd.customer_type is 'Contains the list of available Customer Types (e.g. Individual, Organization, etc.)';

insert into lzd.customer_type
	( name, created, updated )
values
	( 'Individual', now(), now() ),
	( 'Organization', now(), now() );

create table if not exists lzd.email_type (
	id serial primary key,
	name varchar(128) not null unique,
	created timestamp with time zone not null,
	updated timestamp with time zone not null
);

comment on table lzd.email_type is 'Contains the list of available Email Types (e.g. Home, Work, Primary, etc.)';

insert into lzd.email_type
	( name, created, updated )
values
	( 'Primary', now(), now() ),
	( 'Home', now(), now() ),
	( 'Work', now(), now() );

create table if not exists lzd.organization_type (
	id serial primary key,
	name varchar(128) not null unique,
	created timestamp with time zone not null,
	updated timestamp with time zone not null
);

comment on table lzd.organization_type is 'Contains the list of available Organization Types (e.g. LLC, S-Corp, Corporation, Non-Governmental Organization (NGO), etc.)';

insert into lzd.organization_type
	( name, created, updated )
values
	( 'Corporation', now(), now() );

create table if not exists lzd.phone_type (
	id serial primary key,
	name varchar(128) not null unique,
	created timestamp with time zone not null,
	updated timestamp with time zone not null
);

comment on table lzd.phone_type is 'Contains the list of available Phone Types (e.g. Home, Work, Mobile, etc.)';

insert into lzd.phone_type
	( name, created, updated )
values
	( 'Primary', now(), now() ),
	( 'Home', now(), now() ),
	( 'Work', now(), now() ),
	( 'Mobile', now(), now() );


--
-- User Tables
--

create table if not exists lzd.user (
	id serial primary key,
	logon_name varchar(64) not null unique,
	pass_phrase varchar(1024) not null,
	secret bytea not null,
	created timestamp with time zone not null,
	updated timestamp with time zone not null
);

create unique index if not exists ux_user_lower_logon_name on lzd.user ( lower(logon_name) );

comment on table lzd.user is 'Contains all the users able to access the system - including service/system/admin users';
comment on column lzd.user.logon_name is 'Contains the unencrypted logon name of the user - the user will not be able to accesss the system if they lose or forget their user logon name';
comment on column lzd.user.pass_phrase is 'The pass phrase the for the user in an application managed encrypted form';

create table if not exists lzd.user_password_reset (
	uuid uuid not null primary key default gen_random_uuid(),
	user_id integer not null unique,
	created timestamp with time zone not null,
	updated timestamp with time zone not null,
	updated_by_user integer not null,
	constraint fk_user_password_reset_user foreign key (user_id) references lzd.user (id),
	constraint fk_user_password_reset_user_by foreign key (updated_by_user) references lzd.user (id)
);

create index if not exists ix_user_password_reset_ubu on lzd.user_password_reset ( updated_by_user );

comment on table lzd.user_password_reset is 'Contains an entry for a user that has requested a password reset but the password has not yet been reset by the user';
comment on column lzd.user_password_reset.uuid is 'The UUID corresponding to the outstanding request for password reset';

create table if not exists lzd.user_email (
	id serial primary key,
	user_id integer not null,
	email_type_id integer not null,
	encrypted_email_address bytea not null,
	valid boolean null,
	validation_id integer null,
	created timestamp with time zone not null,
	updated timestamp with time zone not null,
	updated_by_user integer not null,
	constraint fk_user_email_user foreign key (user_id) references lzd.user (id),
	constraint fk_user_email_email_type foreign key (email_type_id) references lzd.email_type (id),
	constraint ck_user_email_validatiopn check (valid is null and validation_id is null) or (valid is not null and validation_id is not null)
);

create index if not exists ix_user_email_ubu on lzd.user_email ( updated_by_user );
create unique index if not exists ux_user_email_user_email_type on lzd.user_email ( user_id, email_type_id );
create index if not exists ix_user_email_validation on lzd.user_email ( validation_id nulls first, valid nulls first ) where validation_id is null and valid is null;

comment on table lzd.user_email is 'Contains the the e-mail addresses of all the users - a user can have more than one e-mail address';
comment on column lzd.user_email.encrypted_email_address is 'The email address in an application managed encrypted form for privacy - it is impossible to look-up a user by e-mail address due to this encryption';
comment on column lzd.user_email.valid is 'True if the email address has been validated, False if validation email sent but not responded to. Null if unchecked';
comment on column lzd.user_email.validation_id is 'Null if unchecked. Populated once email sent to user for validation.';

--
-- Customer Tables
--

create table if not exists lzd.customer (
	id serial primary key,
	customer_type_id integer not null,
	created timestamp with time zone not null,
	updated timestamp with time zone not null,
	updated_by_user integer not null,
	constraint fk_customer_user_by foreign key (updated_by_user) references lzd.user (id),
	constraint fk_customer_type foreign key (customer_type_id) references lzd.customer_type (id)
);

create index if not exists ix_customer_ubu on lzd.customer ( updated_by_user );
create index if not exists ix_customer_customer_type_id on lzd.customer ( customer_type_id );

comment on table lzd.customer is 'Contains all the Customers in the system - a given customer may have many associated persons';


--
-- Person Tables
--

create table if not exists lzd.person (
	id serial primary key,
	encrypted_pii bytea not null,
	created timestamp with time zone not null,
	updated timestamp with time zone not null,
	updated_by_user integer not null,
	constraint fk_person_user_by foreign key (updated_by_user) references lzd.user (id)
);

create index if not exists ix_person_ubu on lzd.person ( updated_by_user );

comment on table lzd.person is 'Contains all the persons in the system - a given person may have man associated customers';
comment on column lzd.person.encrypted_pii is 'Contains an encrypted representation of all the Personally Identifiable Information of the user (e.g. Name, Date-of-Birth, etc)';

create table if not exists lzd.person_customer (
	id serial primary key,
	customer_id integer not null,
	person_id integer not null,
	created timestamp with time zone not null,
	updated timestamp with time zone not null,
	updated_by_user integer not null,
	constraint fk_person_customer_user_by foreign key (updated_by_user) references lzd.user (id),
	constraint fk_person_customer_customer foreign key (customer_id) references lzd.customer (id),
	constraint fk_person_customer_person foreign key (person_id) references lzd.person (id)
);

create index if not exists ix_person_customer_ubu on lzd.person_customer ( updated_by_user );
create index if not exists ix_person_customer_customer on lzd.person_customer ( customer_id );
create index if not exists ix_person_customer_person on lzd.person_customer ( person_id );

comment on table lzd.person_customer is 'Associates persons to customers and contains any relevant data particular to that association';

create table if not exists lzd.person_user (
	id serial primary key,
	person_id integer not null,
	user_id integer not null,
	created timestamp with time zone not null,
	updated timestamp with time zone not null,
	updated_by_user integer not null,
	constraint fk_person_user_user_by foreign key (updated_by_user) references lzd.user (id),
	constraint fk_person_user_person foreign key (person_id) references lzd.person (id),
	constraint fk_person_user_user foreign key (user_id) references lzd.user (id)
);

create index if not exists ix_person_user_ubu on lzd.person_user ( updated_by_user );
create unique index if not exists ix_person_user_person on lzd.person_user ( person_id );
create index if not exists ix_person_user_user on lzd.person_user ( user_id );

comment on table lzd.person_user is 'Associates persons to users - there can be only one person per user but a person can associate to multiple users';
