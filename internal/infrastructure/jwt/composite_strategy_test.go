package jwt

import (
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestCompositeStrategyIntegration(t *testing.T) {
	// Create temporary directory for test keys
	tempDir, err := os.MkdirTemp("", "jwt-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	// Create test config
	cfg := &config.Config{
		JWTAccessDuration:  domain.DefaultAccessTokenDuration,
		JWTRefreshDuration: domain.DefaultRefreshTokenDuration,
		JWTKeyPath:         filepath.Join(tempDir, "test-key"),
		VaultAddress:       "http://localhost:8200",
		VaultToken:         "test-token",
		VaultMountPath:     "transit",
		VaultKeyName:       "test-key",
		VaultRoleName:      "test-role",
		VaultAuthMethod:    "token",
		VaultRetryCount:    3,
		VaultRetryDelay:    time.Second,
		VaultTimeout:       time.Second * 5,
	}

	t.Run("new strategy", func(t *testing.T) {
		strategy := NewCompositeStrategy(cfg, logger)
		assert.NotNil(t, strategy)
		assert.NotNil(t, strategy.GetPublicKey())
		assert.NotEmpty(t, strategy.GetKeyID())
	})

	t.Run("sign and validate token", func(t *testing.T) {
		strategy := NewCompositeStrategy(cfg, logger)

		// Create claims
		userID := ulid.Make()
		claims := &domain.Claims{
			Roles: []string{"user"},
			RegisteredClaims: jwt.RegisteredClaims{
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
		strategy := NewCompositeStrategy(cfg, logger)

		// Get initial key ID
		initialKeyID := strategy.GetKeyID()

		// Rotate key
		err := strategy.RotateKey()
		require.NoError(t, err)

		// Check key ID changed
		assert.NotEqual(t, initialKeyID, strategy.GetKeyID())
	})

	t.Run("token durations", func(t *testing.T) {
		strategy := NewCompositeStrategy(cfg, logger)

		assert.Equal(t, domain.DefaultAccessTokenDuration, strategy.GetAccessDuration())
		assert.Equal(t, domain.DefaultRefreshTokenDuration, strategy.GetRefreshDuration())
	})

	t.Run("try vault", func(t *testing.T) {
		strategy := NewCompositeStrategy(cfg, logger)

		// Try to switch to Vault (should fail because Vault is not available)
		err := strategy.(*compositeStrategy).TryVault()
		assert.Error(t, err)
	})

	t.Run("get last rotation", func(t *testing.T) {
		strategy := NewCompositeStrategy(cfg, logger)

		lastRotation := strategy.GetLastRotation()
		assert.NotZero(t, lastRotation)
		assert.True(t, time.Since(lastRotation) < time.Minute)
	})

	t.Run("get public key", func(t *testing.T) {
		strategy := NewCompositeStrategy(cfg, logger)

		publicKey := strategy.GetPublicKey()
		assert.NotNil(t, publicKey)
		assert.IsType(t, &rsa.PublicKey{}, publicKey)
	})

	t.Run("get key ID", func(t *testing.T) {
		strategy := NewCompositeStrategy(cfg, logger)

		keyID := strategy.GetKeyID()
		assert.NotEmpty(t, keyID)
	})
}
