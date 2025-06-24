package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret-key"
	expiresIn := 1 * time.Hour

	// Test creating a valid JWT
	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	// Test validating the JWT
	validatedUserID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("Failed to validate JWT: %v", err)
	}

	if validatedUserID != userID {
		t.Errorf("User ID mismatch: got %v, want %v", validatedUserID, userID)
	}
}

func TestValidateJWTWithWrongSecret(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret-key"
	wrongSecret := "wrong-secret-key"
	expiresIn := 1 * time.Hour

	// Create JWT with correct secret
	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	// Try to validate with wrong secret
	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Error("Expected error when validating with wrong secret, but got nil")
	}
}

func TestValidateExpiredJWT(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret-key"
	expiresIn := -1 * time.Hour // Already expired

	// Create an expired JWT
	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	// Try to validate expired token
	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Error("Expected error when validating expired token, but got nil")
	}
}

func TestValidateInvalidJWT(t *testing.T) {
	secret := "test-secret-key"
	
	// Test with malformed token
	_, err := ValidateJWT("invalid.token.here", secret)
	if err == nil {
		t.Error("Expected error when validating invalid token, but got nil")
	}

	// Test with empty token
	_, err = ValidateJWT("", secret)
	if err == nil {
		t.Error("Expected error when validating empty token, but got nil")
	}
}

func TestHashAndCheckPassword(t *testing.T) {
	password := "test-password-123"

	// Test hashing password
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Test checking correct password
	err = CheckPasswordHash(password, hash)
	if err != nil {
		t.Errorf("Failed to verify correct password: %v", err)
	}

	// Test checking wrong password
	err = CheckPasswordHash("wrong-password", hash)
	if err == nil {
		t.Error("Expected error when checking wrong password, but got nil")
	}
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name        string
		authHeader  string
		expectToken string
		expectError bool
	}{
		{
			name:        "Valid Bearer token",
			authHeader:  "Bearer valid-token-123",
			expectToken: "valid-token-123",
			expectError: false,
		},
		{
			name:        "Bearer with extra spaces",
			authHeader:  "Bearer   token-with-spaces   ",
			expectToken: "token-with-spaces",
			expectError: false,
		},
		{
			name:        "No Authorization header",
			authHeader:  "",
			expectToken: "",
			expectError: true,
		},
		{
			name:        "Wrong auth type",
			authHeader:  "Basic dXNlcjpwYXNz",
			expectToken: "",
			expectError: true,
		},
		{
			name:        "Malformed header",
			authHeader:  "Bearer",
			expectToken: "",
			expectError: true,
		},
		{
			name:        "Case insensitive bearer",
			authHeader:  "bearer lowercase-token",
			expectToken: "lowercase-token",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			token, err := GetBearerToken(headers)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if token != tt.expectToken {
					t.Errorf("Token mismatch: got %q, want %q", token, tt.expectToken)
				}
			}
		})
	}
}