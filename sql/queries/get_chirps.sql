-- name: GetChirps :many
select * from chirps
order by created_at;
