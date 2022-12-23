create table token_instance
(
    uuid uuid DEFAULT uuid_generate_v4(),
    name varchar(255) not null,
    data text not null, -- base64 encoded pkcs12 keystore data
    attributes text,
    primary key (uuid)
);