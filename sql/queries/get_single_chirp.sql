-- name: GetSingleChirp :one
select * from chirps
where id = $1;
