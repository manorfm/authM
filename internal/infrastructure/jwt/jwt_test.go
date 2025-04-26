package jwt

import (
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

func TestJWT(t *testing.T) {
	secret := "test-secret"
	accessDuration := 15 * time.Minute
	refreshDuration := 24 * time.Hour

	jwt := New(secret, accessDuration, refreshDuration)

	userID := ulid.Make()
	roles := []string{"user", "admin"}

	t.Run("generate and validate token pair", func(t *testing.T) {
		// Generate token pair
		tokenPair, err := jwt.GenerateTokenPair(userID, roles)
		if err != nil {
			t.Fatalf("GenerateTokenPair() error = %v", err)
		}

		// Validate access token
		claims, err := jwt.ValidateToken(tokenPair.AccessToken)
		if err != nil {
			t.Fatalf("ValidateToken() error = %v", err)
		}

		if claims.UserID != userID {
			t.Errorf("expected user ID %v, got %v", userID, claims.UserID)
		}

		if len(claims.Roles) != len(roles) {
			t.Errorf("expected %d roles, got %d", len(roles), len(claims.Roles))
		}

		// Check if all roles are present
		roleMap := make(map[string]bool)
		for _, role := range claims.Roles {
			roleMap[role] = true
		}

		for _, role := range roles {
			if !roleMap[role] {
				t.Errorf("role %s not found in claims", role)
			}
		}
	})

	t.Run("validate invalid token", func(t *testing.T) {
		_, err := jwt.ValidateToken("invalid-token")
		if err == nil {
			t.Error("expected error for invalid token")
		}
	})

	t.Run("validate expired token", func(t *testing.T) {
		// Create a token with very short expiration
		jwt := New(secret, time.Millisecond, refreshDuration)
		tokenPair, err := jwt.GenerateTokenPair(userID, roles)
		if err != nil {
			t.Fatalf("GenerateTokenPair() error = %v", err)
		}

		// Wait for token to expire
		time.Sleep(2 * time.Millisecond)

		_, err = jwt.ValidateToken(tokenPair.AccessToken)
		if err == nil {
			t.Error("expected error for expired token")
		}
	})
}
