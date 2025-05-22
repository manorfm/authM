package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestVaultStrategy(t *testing.T) {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	config := &domain.VaultConfig{
		Address:    "http://localhost:8200",
		Token:      "test-token",
		MountPath:  "transit",
		KeyName:    "test-key",
		RoleName:   "test-role",
		AuthMethod: "token",
		RetryCount: 3,
		RetryDelay: time.Second,
		Timeout:    time.Second * 5,
	}

	t.Run("new strategy", func(t *testing.T) {
		strategy, err := NewVaultStrategy(config, logger)
		require.Error(t, err) // Should fail because Vault is not available
		assert.Nil(t, strategy)
	})

	t.Run("token durations", func(t *testing.T) {
		// Create a mock Vault strategy
		strategy := &vaultStrategy{
			config: config,
			logger: logger,
		}

		assert.Equal(t, domain.DefaultAccessTokenDuration, strategy.GetAccessDuration())
		assert.Equal(t, domain.DefaultRefreshTokenDuration, strategy.GetRefreshDuration())
	})

	t.Run("key rotation", func(t *testing.T) {
		// Create a mock Vault strategy
		strategy := &vaultStrategy{
			config: config,
			logger: logger,
			client: nil, // simula ausência de client
		}

		err := strategy.RotateKey()
		assert.Error(t, err) // Deve retornar erro se client for nil
	})

	t.Run("get public key", func(t *testing.T) {
		// Create a mock Vault strategy
		strategy := &vaultStrategy{
			config: config,
			logger: logger,
		}

		publicKey := strategy.GetPublicKey()
		assert.Nil(t, publicKey) // Should be nil because Vault is not available
	})

	t.Run("get key ID", func(t *testing.T) {
		// Create a mock Vault strategy
		strategy := &vaultStrategy{
			config: config,
			logger: logger,
		}

		keyID := strategy.GetKeyID()
		assert.Empty(t, keyID) // Should be empty because Vault is not available
	})

	t.Run("get last rotation", func(t *testing.T) {
		// Create a mock Vault strategy
		strategy := &vaultStrategy{
			config:       config,
			logger:       logger,
			lastRotation: time.Now(),
		}

		lastRotation := strategy.GetLastRotation()
		assert.NotZero(t, lastRotation)
	})

	t.Run("sign token", func(t *testing.T) {
		// Create a mock Vault strategy
		strategy := &vaultStrategy{
			config: config,
			logger: logger,
		}

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

		token, err := strategy.Sign(claims)
		require.Error(t, err) // Should fail because Vault is not available
		assert.Empty(t, token)
	})
}
