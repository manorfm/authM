package jwt

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type jwtService struct {
	strategy  domain.JWTStrategy
	logger    *zap.Logger
	mu        sync.RWMutex
	cache     *jwksCache
	blacklist map[string]time.Time // tokenID -> expiration
}

type jwksCache struct {
	keys     map[string]interface{}
	lastSync time.Time
	mu       sync.RWMutex
}

func newJWKSCache() *jwksCache {
	return &jwksCache{
		keys:     make(map[string]interface{}),
		lastSync: time.Time{},
	}
}

func NewJWTService(strategy domain.JWTStrategy, logger *zap.Logger) domain.JWTService {
	/*
		// Create JWT configuration
		jwtConfig := &domain.JWTConfig{
			AccessDuration:  cfg.JWTAccessDuration,
			RefreshDuration: cfg.JWTRefreshDuration,
		}

		// Validate JWT configuration
		if err := jwtConfig.Validate(); err != nil {
			logger.Fatal("Invalid JWT configuration", zap.Error(err))
		}

		// Create Vault strategy
		vaultConfig := &domain.VaultConfig{
			Address:         cfg.VaultAddress,
			Token:           cfg.VaultToken,
			MountPath:       cfg.VaultMountPath,
			KeyName:         cfg.VaultKeyName,
			RoleName:        cfg.VaultRoleName,
			AuthMethod:      cfg.VaultAuthMethod,
			RetryCount:      cfg.VaultRetryCount,
			RetryDelay:      cfg.VaultRetryDelay,
			Timeout:         cfg.VaultTimeout,
			AccessDuration:  cfg.JWTAccessDuration,
			RefreshDuration: cfg.JWTRefreshDuration,
		}

		vaultStrategy, err := NewVaultStrategy(vaultConfig, logger)
		if err != nil {
			logger.Warn("Failed to create Vault strategy, falling back to local strategy",
				zap.Error(err))
		}

		// Create local strategy
		localConfig := &domain.LocalConfig{
			KeyPath:         cfg.JWTKeyPath,
			AccessDuration:  cfg.JWTAccessDuration,
			RefreshDuration: cfg.JWTRefreshDuration,
		}

		localStrategy, err := NewLocalStrategy(localConfig, logger)
		if err != nil {
			logger.Fatal("Failed to create local strategy", zap.Error(err))
		}

		// Create composite strategy
		strategy := NewCompositeStrategy(vaultStrategy, localStrategy, logger)
	*/

	return &jwtService{
		strategy:  strategy,
		logger:    logger,
		cache:     newJWKSCache(),
		blacklist: make(map[string]time.Time),
	}
}

// ValidateToken validates a JWT token and returns the claims
func (j *jwtService) ValidateToken(tokenString string) (*domain.Claims, error) {

	j.mu.RLock()
	defer j.mu.RUnlock()

	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &domain.Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			j.logger.Error("Invalid signing method", zap.String("token_id", tokenString))
			return nil, domain.ErrInvalidSigningMethod
		}

		// Get public key
		publicKey := j.strategy.GetPublicKey()
		if publicKey == nil {
			j.logger.Error("Invalid public key", zap.String("token_id", tokenString))
			return nil, domain.ErrInvalidToken
		}

		return publicKey, nil
	})

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			j.logger.Warn("Token expired (parser)",
				zap.Error(err),
				zap.String("error_type", fmt.Sprintf("%T", err)))
			return nil, domain.ErrTokenExpired
		case errors.Is(err, jwt.ErrTokenMalformed):
			j.logger.Error("Malformed token",
				zap.Error(err))
			return nil, domain.ErrInvalidToken
		default:
			j.logger.Error("Failed to parse token (generic)",
				zap.Error(err),
				zap.String("error_type", fmt.Sprintf("%T", err)))
			return nil, domain.ErrInvalidToken
		}
	}

	claims, ok := token.Claims.(*domain.Claims)
	if !ok {
		j.logger.Error("Invalid token (not valid)",
			zap.String("token_id", claims.ID))
		return nil, domain.ErrInvalidToken
	}

	// Validate claims
	if err := claims.Valid(); err != nil {
		j.logger.Error("Invalid claims (claims.Valid)",
			zap.Error(err),
			zap.String("token_id", claims.ID),
			zap.String("subject", claims.Subject))
		if errors.Is(err, domain.ErrTokenExpired) {
			j.logger.Warn("Token expired (claims.Valid)",
				zap.Error(err),
				zap.String("token_id", claims.ID))
			return nil, domain.ErrTokenExpired
		}
		return nil, domain.ErrInvalidClaims
	}

	// Additional validation
	if claims.Subject == "" {
		j.logger.Error("Missing subject in token",
			zap.String("token_id", claims.ID))
		return nil, domain.ErrInvalidClaims
	}

	// Check blacklist
	if j.IsTokenBlacklisted(claims.ID) {
		j.logger.Warn("Token is blacklisted", zap.String("token_id", claims.ID))
		return nil, domain.ErrTokenBlacklisted
	}
	return claims, nil
}

func (j *jwtService) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	// Check cache first
	j.cache.mu.RLock()
	if !j.cache.lastSync.IsZero() && time.Since(j.cache.lastSync) < domain.JWKSCacheDuration {
		keys := j.cache.keys
		j.cache.mu.RUnlock()
		return keys, nil
	}
	j.cache.mu.RUnlock()

	// Cache miss or expired, generate new JWKS
	publicKey := j.strategy.GetPublicKey()
	if publicKey == nil {
		j.logger.Error("Failed to get public key")
		return nil, domain.ErrInvalidClient
	}

	jwk, err := convertToJWK(publicKey, j.strategy.GetKeyID())
	if err != nil {
		j.logger.Error("Failed to convert public key to JWK", zap.Error(err))
		return nil, domain.ErrInvalidKeyConfig
	}

	keys := map[string]interface{}{
		"keys": []map[string]interface{}{jwk},
	}

	// Update cache
	j.cache.mu.Lock()
	j.cache.keys = keys
	j.cache.lastSync = time.Now()
	j.cache.mu.Unlock()

	return keys, nil
}

// GenerateTokenPair generates a new pair of access and refresh tokens
func (j *jwtService) GenerateTokenPair(userID ulid.ULID, roles []string) (*domain.TokenPair, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	// Generate access token
	accessTokenID := ulid.Make().String()
	accessClaims := domain.Claims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.strategy.GetAccessDuration())),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        accessTokenID,
		},
	}

	accessToken, err := j.strategy.Sign(&accessClaims)
	if err != nil {
		j.logger.Error("Failed to sign access token",
			zap.Error(err),
			zap.String("token_id", accessTokenID),
			zap.String("user_id", userID.String()))
		return nil, domain.ErrTokenGeneration
	}

	// Generate refresh token
	refreshTokenID := ulid.Make().String()
	refreshClaims := domain.Claims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.strategy.GetRefreshDuration())),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        refreshTokenID,
		},
	}

	refreshToken, err := j.strategy.Sign(&refreshClaims)
	if err != nil {
		j.logger.Error("Failed to sign refresh token",
			zap.Error(err),
			zap.String("token_id", refreshTokenID),
			zap.String("user_id", userID.String()))
		return nil, domain.ErrTokenGeneration
	}

	j.logger.Debug("Generated token pair",
		zap.String("access_token_id", accessTokenID),
		zap.String("refresh_token_id", refreshTokenID),
		zap.String("user_id", userID.String()),
		zap.String("key_id", j.strategy.GetKeyID()))

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (j *jwtService) GetPublicKey() *rsa.PublicKey {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.strategy.GetPublicKey()
}

// RotateKeys rotates the JWT keys
func (j *jwtService) RotateKeys() error {

	j.mu.Lock()
	defer j.mu.Unlock()

	if err := j.strategy.RotateKey(); err != nil {
		j.logger.Error("Failed to rotate keys", zap.Error(err))
		return domain.ErrInvalidKeyConfig
	}

	// Clear JWKS cache
	j.cache.mu.Lock()
	j.cache.keys = make(map[string]interface{})
	j.cache.lastSync = time.Time{}
	j.cache.mu.Unlock()

	j.logger.Info("JWT keys rotated successfully",
		zap.String("key_id", j.strategy.GetKeyID()),
		zap.Time("rotation_time", j.strategy.GetLastRotation()))

	return nil
}

// BlacklistToken adds a token to the blacklist
func (j *jwtService) BlacklistToken(tokenID string, expiresAt time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.blacklist[tokenID] = expiresAt
	return nil
}

// IsTokenBlacklisted checks if a token is blacklisted
func (j *jwtService) IsTokenBlacklisted(tokenID string) bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	exp, ok := j.blacklist[tokenID]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(j.blacklist, tokenID)
		return false
	}
	return true
}

// TryVault attempts to switch back to the Vault strategy
func (j *jwtService) TryVault() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if composite, ok := j.strategy.(*compositeStrategy); ok {
		return composite.TryVault()
	}
	return domain.ErrInvalidClient
}

// convertToJWK converts an RSA public key to JWK format
func convertToJWK(publicKey *rsa.PublicKey, kid string) (map[string]interface{}, error) {
	if publicKey == nil {
		return nil, domain.ErrInvalidKeyConfig
	}

	// Convert modulus and exponent to Base64URL without padding
	modulusBytes := publicKey.N.Bytes()
	nStr := base64.RawURLEncoding.EncodeToString(modulusBytes)

	eBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(eBytes, uint32(publicKey.E))
	eBytes = bytes.TrimLeft(eBytes, "\x00")
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)

	return map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"alg": "RS256",
		"n":   nStr,
		"e":   eStr,
	}, nil
}
