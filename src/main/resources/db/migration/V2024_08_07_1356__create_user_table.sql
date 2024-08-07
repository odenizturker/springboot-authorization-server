create table if not exists "users"
(
    id                     uuid primary key default gen_random_uuid(),
    first_name             text    not null,
    second_name            text    not null,
    username               text    not null,
    email_address          text    not null,
    password               text    not null,
    registration_completed BOOLEAN not null default false,
    expired                BOOLEAN not null default false,
    locked                 BOOLEAN not null default false,
    credentials_expired    BOOLEAN not null default false,
    enabled                BOOLEAN not null default true
    );

create unique index on "users" (email_address);
create unique index on "users" (username);