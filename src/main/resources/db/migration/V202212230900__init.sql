create table token_instance
(
    uuid uuid not null,
    name varchar(255) not null,
    code varchar(255),
    -- base64 encoded pkcs12 keystore data
    data text not null,
    attributes text,
    primary key (uuid)
);