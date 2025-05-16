package jwt

import (
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

func TestJWT(t *testing.T) {
	accessDuration := 15 * time.Minute
	refreshDuration := 24 * time.Hour

	jwt, err := New(accessDuration, refreshDuration)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

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
		jwt, err := New(time.Millisecond, refreshDuration)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

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

	t.Run("validate valid token", func(t *testing.T) {
		tokenPair, err := jwt.GenerateTokenPair(userID, roles)
		if err != nil {
			t.Fatalf("GenerateTokenPair() error = %v", err)
		}

		claims, err := jwt.ValidateToken(tokenPair.AccessToken)
		if err != nil {
			t.Fatalf("ValidateToken() error = %v", err)
		}

		if claims.Subject != userID.String() {
			t.Errorf("expected subject %s, got %s", userID.String(), claims.Subject)
		}

		if len(claims.Roles) != len(roles) {
			t.Errorf("expected %d roles, got %d", len(roles), len(claims.Roles))
		}
	})
}
