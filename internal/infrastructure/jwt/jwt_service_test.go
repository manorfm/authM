package jwt

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
)

func getJWTServiceWithDuration(t *testing.T, accessDuration, refreshDuration time.Duration) domain.JWTService {
	// Create temporary directory for test keys
	tempDir, err := os.MkdirTemp("", "jwt-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	cfg := &config.Config{
		JWTAccessDuration:  accessDuration,
		JWTRefreshDuration: refreshDuration,
		JWTKeyPath:         filepath.Join(tempDir, "test-key"),
		// Desabilitar Vault para testes
		VaultAddress:   "",
		VaultToken:     "",
		VaultMountPath: "",
		VaultKeyName:   "",
	}

	strategy := NewCompositeStrategy(cfg, logger)
	service := NewJWTService(strategy, logger)
	require.NotNil(t, service)

	return service
}

func getJWTService(t *testing.T) domain.JWTService {
	return getJWTServiceWithDuration(t, domain.DefaultAccessTokenDuration, domain.DefaultRefreshTokenDuration)
}

func TestJWTService_ValidateToken(t *testing.T) {
	service := getJWTService(t)

	// Test valid token
	userID := ulid.Make()
	roles := []string{"ADMIN"}
	tokenPair, err := service.GenerateTokenPair(userID, roles)
	require.NoError(t, err)

	claims, err := service.ValidateToken(tokenPair.AccessToken)
	require.NoError(t, err)
	require.NotNil(t, claims)
	require.Equal(t, userID.String(), claims.Subject)
	require.Equal(t, roles, claims.Roles)

	// Test expired token
	shortService := getJWTServiceWithDuration(t, 1*time.Second, domain.DefaultRefreshTokenDuration)
	expiredUserID := ulid.Make()
	expiredRoles := []string{"USER"}
	expiredTokenPair, err := shortService.GenerateTokenPair(expiredUserID, expiredRoles)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	_, err = shortService.ValidateToken(expiredTokenPair.AccessToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expired")

	// Test invalid token
	invalidToken := "invalid.token.here"
	_, err = service.ValidateToken(invalidToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid token")

	// Test blacklisted token
	blacklistedUserID := ulid.Make()
	blacklistedRoles := []string{"USER"}
	blacklistedTokenPair, err := service.GenerateTokenPair(blacklistedUserID, blacklistedRoles)
	require.NoError(t, err)

	// Obter claims para pegar o ID do token
	blacklistedClaims, err := service.ValidateToken(blacklistedTokenPair.AccessToken)
	require.NoError(t, err)

	// Add token to blacklist usando o ID
	err = service.BlacklistToken(blacklistedClaims.ID, blacklistedClaims.ExpiresAt.Time)
	require.NoError(t, err)

	// Try to validate blacklisted token
	_, err = service.ValidateToken(blacklistedTokenPair.AccessToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "token is blacklisted")
}

func TestJWTService_GenerateTokenPair(t *testing.T) {
	service := getJWTService(t)

	userID := ulid.Make()
	roles := []string{"ADMIN", "USER"}

	tokenPair, err := service.GenerateTokenPair(userID, roles)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenPair.AccessToken)
	assert.NotEmpty(t, tokenPair.RefreshToken)

	// Validar o token de acesso
	claims, err := service.ValidateToken(tokenPair.AccessToken)
	require.NoError(t, err)
	assert.NotNil(t, claims)
	if claims != nil {
		assert.Equal(t, userID.String(), claims.Subject)
		assert.Equal(t, roles, claims.Roles)
	}

	// Validar o token de refresh
	claims, err = service.ValidateToken(tokenPair.RefreshToken)
	require.NoError(t, err)
	assert.NotNil(t, claims)
	if claims != nil {
		assert.Equal(t, userID.String(), claims.Subject)
		assert.Equal(t, roles, claims.Roles)
	}
}

func TestJWTService_GetJWKS(t *testing.T) {
	service := getJWTService(t)

	ctx := context.Background()
	jwks, err := service.GetJWKS(ctx)
	require.NoError(t, err)
	require.NotNil(t, jwks)

	// Verificar se o JWKS contém as chaves esperadas
	keys, ok := jwks["keys"].([]map[string]interface{})
	require.True(t, ok, "JWKS should contain a 'keys' array")
	assert.NotEmpty(t, keys, "JWKS should contain at least one key")

	// Verificar se cada chave tem os campos obrigatórios
	for _, key := range keys {
		assert.Contains(t, key, "kty", "Key should have 'kty' field")
		assert.Contains(t, key, "kid", "Key should have 'kid' field")
		assert.Contains(t, key, "use", "Key should have 'use' field")
		assert.Contains(t, key, "alg", "Key should have 'alg' field")
		assert.Contains(t, key, "n", "Key should have 'n' field")
		assert.Contains(t, key, "e", "Key should have 'e' field")
	}
}

func TestJWTService_RotateKeys(t *testing.T) {
	service := getJWTService(t)

	// Gerar token com a chave antiga
	userID := ulid.Make()
	roles := []string{"ADMIN"}

	tokenPair1, err := service.GenerateTokenPair(userID, roles)
	require.NoError(t, err)

	// Validar token com a chave antiga
	validatedClaims, err := service.ValidateToken(tokenPair1.AccessToken)
	require.NoError(t, err)
	assert.NotNil(t, validatedClaims)
	if validatedClaims != nil {
		assert.Equal(t, userID.String(), validatedClaims.Subject)
		assert.Contains(t, validatedClaims.Roles, "ADMIN")
	}

	// Rotacionar chaves
	err = service.RotateKeys()
	require.NoError(t, err)

	// Gerar novo token com a nova chave
	tokenPair2, err := service.GenerateTokenPair(userID, roles)
	require.NoError(t, err)

	// Validar novo token
	validatedClaims, err = service.ValidateToken(tokenPair2.AccessToken)
	require.NoError(t, err)
	assert.NotNil(t, validatedClaims)
	if validatedClaims != nil {
		assert.Equal(t, userID.String(), validatedClaims.Subject)
		assert.Contains(t, validatedClaims.Roles, "ADMIN")
	}

	// Verificar se o token antigo é inválido após a rotação
	_, err = service.ValidateToken(tokenPair1.AccessToken)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "signature"), "Error should indicate invalid token")

	// Verificar se o JWKS foi atualizado
	ctx := context.Background()
	jwks, err := service.GetJWKS(ctx)
	require.NoError(t, err)
	require.NotNil(t, jwks)
	keys := jwks["keys"].([]map[string]interface{})
	assert.NotEmpty(t, keys)
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

func TestJWTService_BlacklistToken(t *testing.T) {
	service := getJWTService(t)

	userID := ulid.Make()
	roles := []string{"ADMIN"}

	// Gerar um token válido
	tokenPair, err := service.GenerateTokenPair(userID, roles)
	require.NoError(t, err)

	// Verificar que o token é válido antes de ser adicionado à blacklist
	claims, err := service.ValidateToken(tokenPair.AccessToken)
	require.NoError(t, err)
	assert.NotNil(t, claims)

	// Adicionar o token à blacklist usando o ID do token
	err = service.BlacklistToken(claims.ID, claims.ExpiresAt.Time)
	require.NoError(t, err)

	// Verificar que o token é rejeitado após ser adicionado à blacklist
	_, err = service.ValidateToken(tokenPair.AccessToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blacklisted")

	// Verificar que o token de refresh não é afetado
	claims, err = service.ValidateToken(tokenPair.RefreshToken)
	require.NoError(t, err)
	assert.NotNil(t, claims)
}

func TestJWTService_GetPublicKey(t *testing.T) {
	service := getJWTService(t)

	// Obter a chave pública
	key := service.GetPublicKey()
	require.NotNil(t, key)

	// Verificar se a chave pode ser usada para validar um token
	userID := ulid.Make()
	roles := []string{"ADMIN"}

	tokenPair, err := service.GenerateTokenPair(userID, roles)
	require.NoError(t, err)

	claims, err := service.ValidateToken(tokenPair.AccessToken)
	require.NoError(t, err)
	assert.NotNil(t, claims)
	if claims != nil {
		assert.Equal(t, userID.String(), claims.Subject)
		assert.Contains(t, claims.Roles, "ADMIN")
	}
}
