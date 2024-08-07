create table if not exists authorities
(
    id        uuid primary key default gen_random_uuid(),
    authority text not null
    );

create unique index on authorities (authority);

insert into authorities(authority)
values ('ROLE_USER');