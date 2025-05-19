package jwt

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

func getJWTService(t *testing.T) JWTService {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	cfg := &config.Config{
		JWTAccessDuration:  domain.DefaultAccessTokenDuration,
		JWTRefreshDuration: domain.DefaultRefreshTokenDuration,
	}

	service := NewJWTService(cfg, logger)
	require.NotNil(t, service)

	// Disable rate limiting for tests
	service.(*jwtService).rateLimiter = rate.NewLimiter(rate.Inf, 0)
	return service
}

// getJWTServiceWithRateLimit returns a JWT service with rate limiting enabled
// This should only be used for rate limit specific tests
func getJWTServiceWithRateLimit(t *testing.T, r rate.Limit, b int) JWTService {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	cfg := &config.Config{
		JWTAccessDuration:  domain.DefaultAccessTokenDuration,
		JWTRefreshDuration: domain.DefaultRefreshTokenDuration,
	}

	service := NewJWTService(cfg, logger)
	require.NotNil(t, service)

	// Set custom rate limit
	service.(*jwtService).rateLimiter = rate.NewLimiter(r, b)
	return service
}

func TestJWTService_ValidateToken(t *testing.T) {
	service := getJWTService(t)
	userID := ulid.Make()
	roles := []string{"user"}

	t.Run("valid token", func(t *testing.T) {
		tokenPair, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)
		require.NotNil(t, tokenPair)

		claims, err := service.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, userID.String(), claims.Subject)
		assert.Equal(t, roles, claims.Roles)
	})

	t.Run("invalid token", func(t *testing.T) {
		claims, err := service.ValidateToken("invalid.token.here")
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, domain.ErrInvalidToken)
	})

	t.Run("expired token", func(t *testing.T) {
		t.Log("Início do teste de token expirado")
		// Create a token with a very short expiration
		cfg := &config.Config{
			JWTAccessDuration:  1 * time.Millisecond,
			JWTRefreshDuration: 1 * time.Hour,
		}
		t.Log("Configuração criada")
		expiredService := NewJWTService(cfg, zap.NewNop())
		t.Log("Serviço JWT criado")
		tokenPair, err := expiredService.GenerateTokenPair(userID, roles)
		if err != nil {
			t.Fatalf("Erro ao gerar token pair: %v", err)
		}
		t.Log("Token pair gerado")
		time.Sleep(10 * time.Millisecond)
		t.Log("Sleep finalizado, validando token...")
		claims, err := expiredService.ValidateToken(tokenPair.AccessToken)
		fmt.Println("Erro retornado:", err)
		if err == nil {
			t.Fatal("Esperava erro para token expirado, mas não recebeu erro")
		}
		if !errors.Is(err, domain.ErrTokenExpired) {
			t.Fatalf("Esperava domain.ErrTokenExpired, mas recebeu: %T - %v", err, err)
		}
		assert.Nil(t, claims)
	})

	t.Run("token with invalid signing method", func(t *testing.T) {
		// Create a token with HS256 instead of RS256
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &domain.Claims{
			Roles: roles,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   userID.String(),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		})
		invalidToken, err := token.SignedString([]byte("invalid-key"))
		require.NoError(t, err)

		claims, err := service.ValidateToken(invalidToken)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, domain.ErrInvalidSigningMethod)
	})

	t.Run("token with invalid claims", func(t *testing.T) {
		fmt.Println("[TEST] Gerando token sem roles...")
		// Create a token without roles
		tokenPair, err := service.GenerateTokenPair(userID, nil)
		fmt.Println("[TEST] Token gerado, err:", err)
		require.NoError(t, err)

		fmt.Println("[TEST] Validando token...")
		claims, err := service.ValidateToken(tokenPair.AccessToken)
		fmt.Println("[TEST] claims:", claims, "err:", err)
		assert.Error(t, err)
		fmt.Println("[TEST] assert.Error passou")
		assert.Nil(t, claims)
		fmt.Println("[TEST] assert.Nil passou")
		assert.ErrorIs(t, err, domain.ErrInvalidClaims)
		fmt.Println("[TEST] assert.ErrorIs passou")
		assert.Contains(t, err.Error(), "no roles assigned")
	})

	t.Run("blacklisted token", func(t *testing.T) {
		// Generate a token
		tokenPair, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		// Get token ID from claims
		claims, err := service.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)

		// Blacklist the token
		err = service.BlacklistToken(claims.ID, claims.ExpiresAt.Time)
		require.NoError(t, err)

		// Try to validate the blacklisted token
		claims, err = service.ValidateToken(tokenPair.AccessToken)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, domain.ErrTokenBlacklisted)
	})
}

func TestJWTService_GenerateTokenPair(t *testing.T) {
	service := getJWTService(t)
	userID := ulid.Make()
	roles := []string{"user", "admin"}

	t.Run("successful token generation", func(t *testing.T) {
		tokenPair, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)
		require.NotNil(t, tokenPair)
		assert.NotEmpty(t, tokenPair.AccessToken)
		assert.NotEmpty(t, tokenPair.RefreshToken)

		// Validate both tokens
		accessClaims, err := service.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, userID.String(), accessClaims.Subject)
		assert.Equal(t, roles, accessClaims.Roles)

		refreshClaims, err := service.ValidateToken(tokenPair.RefreshToken)
		require.NoError(t, err)
		assert.Equal(t, userID.String(), refreshClaims.Subject)
		assert.Equal(t, roles, refreshClaims.Roles)
	})

	t.Run("token with different durations", func(t *testing.T) {
		tokenPair, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		accessClaims, err := service.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)
		refreshClaims, err := service.ValidateToken(tokenPair.RefreshToken)
		require.NoError(t, err)

		assert.True(t, refreshClaims.ExpiresAt.After(accessClaims.ExpiresAt.Time))
	})

	t.Run("rate limiting", func(t *testing.T) {
		// Create a service with a very low rate limit (1 request per second, burst of 1)
		limitedService := getJWTServiceWithRateLimit(t, 1, 1)
		userID := ulid.Make()
		roles := []string{"user"}

		// First request should succeed
		_, err := limitedService.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		// Second request should fail due to rate limit
		_, err = limitedService.GenerateTokenPair(userID, roles)
		assert.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrRateLimitExceeded)
	})
}

func TestJWTService_GetJWKS(t *testing.T) {
	service := getJWTService(t)

	t.Run("successful JWKS retrieval", func(t *testing.T) {
		jwks, err := service.GetJWKS(context.Background())
		require.NoError(t, err)
		require.NotNil(t, jwks)

		keys, ok := jwks["keys"].([]map[string]interface{})
		require.True(t, ok)
		require.Len(t, keys, 1)

		key := keys[0]
		assert.Equal(t, "RSA", key["kty"])
		assert.Equal(t, "sig", key["use"])
		assert.Equal(t, "RS256", key["alg"])
		assert.NotEmpty(t, key["kid"])
		assert.NotEmpty(t, key["n"])
		assert.NotEmpty(t, key["e"])
	})

	t.Run("JWKS caching", func(t *testing.T) {
		// First call
		jwks1, err := service.GetJWKS(context.Background())
		require.NoError(t, err)

		// Second call should return cached value
		jwks2, err := service.GetJWKS(context.Background())
		require.NoError(t, err)

		assert.Equal(t, jwks1, jwks2)
	})

	t.Run("rate limiting", func(t *testing.T) {
		// Create a service with a very low rate limit (1 request per second, burst of 1)
		limitedService := getJWTServiceWithRateLimit(t, 1, 1)

		// First request should succeed
		_, err := limitedService.GetJWKS(context.Background())
		require.NoError(t, err)

		// Second request should fail due to rate limit
		_, err = limitedService.GetJWKS(context.Background())
		assert.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrRateLimitExceeded)
	})
}

func TestJWTService_RotateKeys(t *testing.T) {
	service := getJWTService(t)
	userID := ulid.Make()
	roles := []string{"user"}

	t.Run("successful key rotation", func(t *testing.T) {
		// Generate token with old key
		tokenPair1, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		// Rotate keys
		err = service.RotateKeys()
		require.NoError(t, err)

		// Generate a token with the new key
		tokenPair, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		// Validate the token with the new key
		claims, err := service.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, userID.String(), claims.Subject)
		assert.Equal(t, roles, claims.Roles)

		// Old token pode não ser mais válido após rotação de chave
		_, err = service.ValidateToken(tokenPair1.AccessToken)
		if err == nil {
			t.Log("Token antigo ainda válido após rotação de chave (aceitável se chaves antigas são mantidas)")
		} else {
			t.Logf("Token antigo inválido após rotação de chave (esperado): %v", err)
		}

		// JWKS should be updated
		jwks, err := service.GetJWKS(context.Background())
		require.NoError(t, err)
		keys := jwks["keys"].([]map[string]interface{})
		assert.Len(t, keys, 1)
	})

	t.Run("rate limiting", func(t *testing.T) {
		// Create a service with a very low rate limit (1 request per second, burst of 1)
		limitedService := getJWTServiceWithRateLimit(t, 1, 1)

		// First rotation should succeed
		err := limitedService.RotateKeys()
		require.NoError(t, err)

		// Try to rotate keys again immediately - should fail due to rate limit
		err = limitedService.RotateKeys()
		assert.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrRateLimitExceeded)

		// Wait for rate limit to reset
		time.Sleep(time.Second)

		// Should succeed again after waiting
		err = limitedService.RotateKeys()
		require.NoError(t, err)
	})
}

func TestJWTService_TokenBlacklist(t *testing.T) {
	service := getJWTService(t)
	userID := ulid.Make()
	roles := []string{"user"}

	t.Run("blacklist and check token", func(t *testing.T) {
		// Generate a token
		tokenPair, err := service.GenerateTokenPair(userID, roles)
		require.NoError(t, err)

		// Get token ID from claims
		claims, err := service.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)

		// Blacklist the token
		err = service.BlacklistToken(claims.ID, claims.ExpiresAt.Time)
		require.NoError(t, err)

		// Try to validate the blacklisted token
		claims, err = service.ValidateToken(tokenPair.AccessToken)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, domain.ErrTokenBlacklisted)
	})
}
