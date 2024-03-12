# Chirpy

Chirpy is twitter-like clone API for sending short messages. This is a guided project is a part of boot.dev program.

## API resources

### User 

#### Create User

POST /api/users 
```json
{
    "email": "example@mail.com",
    "password": "123456"     

}
```
RESPONSE
```json
{
    "email": "example@mail.com",
    "id": 1,
    "token": "this_is_jwt_token"
}
```
#### Update User

PUT /api/users 

Header:
```json
{
    "Authorization": "Bearer this_is_jwt_token"
}
```
Body:
```json
{
    "email": "example@mail.com",
    "id": 1
}
```
RESPONSE
```json
{
    "email": "example@mail.com",
    "id": 1,
    "token": "this_is_jwt_token"
}
```
#### Login User

PUT /api/login 
```json
{
    "email": "example@mail.com",
    "password": "123456"
}
```
RESPONSE
```json
{
    "email": "example@mail.com",
    "id": 1,
    "token": "this_is_access_jwt_token",
    "refresh_token": "this_is_refresh_jwt_token"
}
```

### Tokens

#### Refresh Token 

POST /api/refresh 
```json
{
    "Authorization": "Bearer this_is_refresh_jwt_token"
}
```
RESPONSE
```json
{
    "token": "this_is_a_new_access_jwt_token"
}
```
#### Revoke Token

POST /api/revoke 
```json
{
    "refresh_token": "this_is_refresh_jwt_token"
}
```

### Chirps (messages)

#### Post a Chirp

POST /api/chirps 

Header:
```json
{
    "Authorization": "Bearer this_is_access_token"
}
```

Body:
```json
{
    "body": "Write your message here!"
}
```
RESPONSE
```json
{
    "id": 1,
    "body": "Write your message here!",
    "author_id": 1
}
```

#### Get chirps

GET /api/chirps 

Available parameters:

author_id: lists chirps from this user
sort: sorts chirps in ascending(**asc** or defauld) or descending(**desc**) order

Usage: Add to the end of url of api call: /api/chirps?author_id=1&sort=desc

RESPONSE
```json
[

{
    "id": 1,
    "body": "Write your message here!",
    "author_id": 1
},
{
    "id": 2,
    "body": "Second message!",
    "author_id": 1
},

]
```

#### Get a singel chirp

GET /api/chirps/{chirpID} 

RESPONSE
```json
{
    "id": 1,
    "body": "Write your message here!",
    "author_id": 1
}
```
#### Delete a Chirp

POST /api/chirps/{chirpID} 

Header:
```json
{
    "Authorization": "Bearer this_is_access_token"
}
```
