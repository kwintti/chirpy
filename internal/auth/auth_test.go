package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func TestHashing(t *testing.T) {
	//Test hashing
	hashed, err := HashPassword("this_is_password")
	require.NoError(t, err)
	require.NotNil(t, hashed)

	//Test comparing hash to password with right value
	err = CheckPasswordHash("this_is_password", hashed)
	require.NoError(t, err)
	
	//Wrong value, should produce error
	err = CheckPasswordHash("this_is_wrong", hashed)
	require.Error(t, err)
}

func TestJWT(t *testing.T) {
	//Test token is valid
	idUUID, err := uuid.Parse("ea6f3461-d69a-47e4-b631-4ef4d9afd249")
	require.NoError(t, err)
	require.NotNil(t, idUUID)

	tokenSigned, err := MakeJWT(idUUID, "this_is_token_secret", 10 * time.Minute)
	require.NoError(t, err)
	id, err := ValidateJWT(tokenSigned, "this_is_token_secret")
	require.NoError(t, err)
	assert.Equal(t, idUUID, id)

	//Test token is invalid
	_, err = ValidateJWT(tokenSigned, "this_is_token_secret_NOTVALID")
	require.Error(t, err)

	//Token is expired
	tokenSigned, err = MakeJWT(idUUID, "this_is_token_secret", 1 * time.Millisecond)
	require.NoError(t, err)
	time.Sleep(10*time.Millisecond)
	_, err = ValidateJWT(tokenSigned, "this_is_token_secret")
	require.Error(t, err)
}

func TestBearer(t *testing.T) {
	//Test Bearer token if present
	header := http.Header{}
	header.Set("Authorization", "Bearer this_is_token_secret")
	token, err := GetBearerToken(header)
	require.NoError(t, err)
	assert.Equal(t, "this_is_token_secret", token)
}

func TestBearerMissing(t *testing.T) {
	// Bearer missing
	header := http.Header{}
	_, err := GetBearerToken(header)
	require.Error(t, err)
}	

func TestBearer_Extra_Spaces(t *testing.T) {
	// Extra Spaces 
	header := http.Header{}
	header.Set("Authorization", "      Bearer      this_is_token_secret    ")
	token, err := GetBearerToken(header)
	require.NoError(t, err)
	assert.Equal(t, "this_is_token_secret", token)
}	
