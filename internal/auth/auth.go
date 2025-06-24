package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPasswordHash compares a password with its hash
func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// MakeJWT creates a new JWT token for a user
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	now := time.Now().UTC()
	
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(tokenSecret))
}

// ValidateJWT validates a JWT token and returns the user ID
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := &jwt.RegisteredClaims{}
	
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.UUID{}, err
	}

	if !token.Valid {
		return uuid.UUID{}, errors.New("invalid token")
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.UUID{}, err
	}

	return userID, nil
}

// GetBearerToken extracts the token from the Authorization header
func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no authorization header found")
	}

	// Split on first space only
	const bearerPrefix = "bearer "
	if len(authHeader) < len(bearerPrefix) {
		return "", errors.New("invalid authorization header format")
	}

	if strings.ToLower(authHeader[:len(bearerPrefix)]) != bearerPrefix {
		return "", errors.New("invalid authorization header format")
	}

	token := strings.TrimSpace(authHeader[len(bearerPrefix):])
	if token == "" {
		return "", errors.New("invalid authorization header format")
	}

	return token, nil
}

// MakeRefreshToken generates a random 256-bit hex-encoded refresh token
func MakeRefreshToken() (string, error) {
	tokenBytes := make([]byte, 32) // 32 bytes = 256 bits
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(tokenBytes), nil
}

// GetAPIKey extracts the API key from the Authorization header
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no authorization header found")
	}

	// Expected format: "ApiKey THE_KEY_HERE"
	const apiKeyPrefix = "ApiKey "
	if len(authHeader) < len(apiKeyPrefix) {
		return "", errors.New("invalid authorization header format")
	}

	if authHeader[:len(apiKeyPrefix)] != apiKeyPrefix {
		return "", errors.New("invalid authorization header format")
	}

	apiKey := strings.TrimSpace(authHeader[len(apiKeyPrefix):])
	if apiKey == "" {
		return "", errors.New("invalid authorization header format")
	}

	return apiKey, nil
}