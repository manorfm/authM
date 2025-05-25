package jwt

import (
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// mockVaultStrategy implements JWTStrategy for testing
type mockVaultStrategy struct{}

func (m *mockVaultStrategy) Sign(claims *domain.Claims) (string, error) {
	return "", domain.ErrInvalidClient
}

func (m *mockVaultStrategy) GetPublicKey() *rsa.PublicKey {
	return nil
}

func (m *mockVaultStrategy) GetKeyID() string {
	return "mock-vault-key"
}

func (m *mockVaultStrategy) RotateKey() error {
	return domain.ErrInvalidClient
}

func (m *mockVaultStrategy) GetLastRotation() time.Time {
	return time.Now()
}

func (m *mockVaultStrategy) GetAccessDuration() time.Duration {
	return domain.DefaultAccessTokenDuration
}

func (m *mockVaultStrategy) GetRefreshDuration() time.Duration {
	return domain.DefaultRefreshTokenDuration
}

func TestLocalStrategy(t *testing.T) {
	// Create temporary directory for test keys
	tempDir, err := os.MkdirTemp("", "jwt-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	config := &domain.LocalConfig{
		KeyPath:         filepath.Join(tempDir, "test-key"),
		AccessDuration:  domain.DefaultAccessTokenDuration,
		RefreshDuration: domain.DefaultRefreshTokenDuration,
	}

	t.Run("new strategy", func(t *testing.T) {
		strategy, err := NewLocalStrategy(config, logger)
		require.NoError(t, err)
		assert.NotNil(t, strategy)
		assert.NotNil(t, strategy.GetPublicKey())
		assert.NotEmpty(t, strategy.GetKeyID())
	})

	t.Run("sign and validate token", func(t *testing.T) {
		strategy, err := NewLocalStrategy(config, logger)
		require.NoError(t, err)

		// Create claims
		userID := ulid.Make()
		claims := &domain.Claims{
			Roles: []string{"user"},
			RegisteredClaims: &jwt.RegisteredClaims{
				Subject:   userID.String(),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ID:        ulid.Make().String(),
			},
		}

		// Sign token
		token, err := strategy.Sign(claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Validate token
		parsedToken, err := jwt.ParseWithClaims(token, &domain.Claims{}, func(token *jwt.Token) (interface{}, error) {
			return strategy.GetPublicKey(), nil
		})
		require.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		parsedClaims, ok := parsedToken.Claims.(*domain.Claims)
		require.True(t, ok)
		assert.Equal(t, userID.String(), parsedClaims.Subject)
		assert.Equal(t, []string{"user"}, parsedClaims.Roles)
	})

	t.Run("rotate key", func(t *testing.T) {
		strategy, err := NewLocalStrategy(config, logger)
		require.NoError(t, err)

		// Get initial key ID
		initialKeyID := strategy.GetKeyID()

		// Rotate key
		err = strategy.RotateKey()
		require.NoError(t, err)

		// Check key ID changed
		assert.NotEqual(t, initialKeyID, strategy.GetKeyID())
	})

	t.Run("token durations", func(t *testing.T) {
		strategy, err := NewLocalStrategy(config, logger)
		require.NoError(t, err)

		assert.Equal(t, domain.DefaultAccessTokenDuration, strategy.GetAccessDuration())
		assert.Equal(t, domain.DefaultRefreshTokenDuration, strategy.GetRefreshDuration())
	})
}
