package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type mockOAuth2Repository struct {
	mock.Mock
}

func TestJWTService_ValidateToken(t *testing.T) {
	accessDuration := 15 * time.Minute
	refreshDuration := 24 * time.Hour

	cfg := &config.Config{
		JWTAccessDuration:  accessDuration,
		JWTRefreshDuration: refreshDuration,
		JWTSecret:          "test_secret",
	}
	jwt := NewJWTService(cfg, zap.NewNop())

	userID := ulid.Make()
	roles := []string{"user", "admin"}

	t.Run("validate invalid token", func(t *testing.T) {
		_, err := jwt.ValidateToken("invalid-token")
		assert.Error(t, err)
	})

	t.Run("validate expired token", func(t *testing.T) {
		// Create a token with very short expiration
		cfg := &config.Config{
			JWTAccessDuration:  1 * time.Millisecond,
			JWTRefreshDuration: refreshDuration,
			JWTSecret:          "test_secret",
		}
		jwt := NewJWTService(cfg, zap.NewNop())

		tokenPair, err := jwt.GenerateTokenPair(userID, roles)
		assert.NoError(t, err)

		// Wait for token to expire
		time.Sleep(2 * time.Millisecond)

		_, err = jwt.ValidateToken(tokenPair.AccessToken)
		assert.Error(t, err)
	})

	t.Run("validate valid token", func(t *testing.T) {
		tokenPair, err := jwt.GenerateTokenPair(userID, roles)
		assert.NoError(t, err)

		claims, err := jwt.ValidateToken(tokenPair.AccessToken)
		assert.NoError(t, err)
		assert.Equal(t, userID.String(), claims.Subject)
		assert.Equal(t, roles, claims.Roles)
	})
}

func getJWTService(t *testing.T) *JWTService {
	cfg := &config.Config{
		JWTAccessDuration:  15 * time.Minute,
		JWTRefreshDuration: 24 * time.Hour,
		JWTSecret:          "test_secret",
	}
	return NewJWTService(cfg, zap.NewNop())
}

func TestJWTService_GetJWKS(t *testing.T) {
	tests := []struct {
		name          string
		service       *JWTService
		expectedError error
		expectedJWKS  map[string]interface{}
	}{
		{
			name:          "successful JWKS retrieval",
			service:       getJWTService(t),
			expectedError: nil,
			expectedJWKS: map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kty": "RSA",
						"use": "sig",
						"kid": "1",
						"alg": "RS256",
						"n":   "test_n",
						"e":   "test_e",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwks, err := tt.service.GetJWKS(context.Background())

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
				assert.Nil(t, jwks)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, jwks)
				assert.Contains(t, jwks, "keys")

				keys, ok := jwks["keys"].([]map[string]interface{})
				assert.True(t, ok)
				assert.Len(t, keys, 1)

				key := keys[0]
				assert.Equal(t, "RSA", key["kty"])
				assert.Equal(t, "sig", key["use"])
				assert.Equal(t, "RS256", key["alg"])
				assert.Equal(t, "1", key["kid"])
			}
		})
	}
}
