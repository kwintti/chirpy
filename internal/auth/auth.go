package auth

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}
	return string(hashedPass), nil
}

func CheckPasswordHash(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return err
	}
	return nil
}


func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
    claims := jwt.RegisteredClaims{
            Issuer: "chirpy",
			IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
            Subject: userID.String(),
            ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    token_signed, err := token.SignedString([]byte(tokenSecret))
    if err != nil {
        return "", err
    }

    return token_signed, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			log.Println("Method doesn't match")
			return nil, fmt.Errorf("Method doesn't match")
		}
		return []byte(tokenSecret), nil

	})
	if err != nil {
		return uuid.UUID{}, err
	}
	userIdString, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.UUID{}, err
	}
	userID, err := uuid.Parse(userIdString)
	if err != nil {
		return uuid.UUID{}, err
	}

	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	auth := headers.Get("Authorization")
	if auth == "" {
		msg := fmt.Errorf("No authorization header detected")
		return "", msg 
	}
	tokenString := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(auth), "Bearer "))

	return tokenString, nil
}
