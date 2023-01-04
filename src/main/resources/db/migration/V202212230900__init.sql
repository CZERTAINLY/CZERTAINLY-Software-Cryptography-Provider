create table token_instance
(
    uuid uuid not null,
    name varchar(255) not null,
    code varchar(255),
    -- base64 encoded pkcs12 keystore data
    data text not null,
    metadata text,
    timestamp timestamp not null,
    primary key (uuid)
);

create table key_data
(
    uuid uuid not null,
    name varchar(255) not null,
    association varchar(255),
    type varchar(255) not null,
    algorithm varchar(255) not null,
    format varchar(255) not null,
    value text not null,
    length int not null,
    metadata text,
    token_instance_uuid uuid not null,
    primary key (uuid)
);

alter table if exists key_data
    add constraint key_data_to_token_instance_uuid_key
    foreign key (token_instance_uuid)
    references token_instance (uuid)
    on update no action on delete cascade;