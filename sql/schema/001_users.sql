-- +goose Up
create table users (
    id uuid default gen_random_uuid() primary key,
    created_at timestamp not null,
    updated_at timestamp not null,
    email varchar (255) unique not null
);

-- +goose Down
drop table users;
