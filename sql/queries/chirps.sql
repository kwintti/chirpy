-- name: NewChirp :one
insert into chirps (id, created_at, updated_at, body, author_id)
values (
    gen_random_uuid(),
    now(),
    now(),
    $1,
    $2
)
returning *;
