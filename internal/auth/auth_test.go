package auth

import (
	"testing"

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
