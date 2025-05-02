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
