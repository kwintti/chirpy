-- +goose Up
create table chirps (
    id uuid default gen_random_uuid() primary key,
    created_at timestamp not null,
    updated_at timestamp not null,
    body varchar (255) not null,
    author_id uuid not null references users on delete cascade 
);

-- +goose Down
drop table chirps;
