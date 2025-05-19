package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// JWTService defines the interface for JWT operations
type JWTService interface {
	ValidateToken(tokenString string) (*domain.Claims, error)
	GetJWKS(ctx context.Context) (map[string]interface{}, error)
	GenerateTokenPair(userID ulid.ULID, roles []string) (*domain.TokenPair, error)
	GetPublicKey() *rsa.PublicKey
	RotateKeys() error
	BlacklistToken(tokenID string, expiresAt time.Time) error
	IsTokenBlacklisted(tokenID string) bool
}

type jwtService struct {
	jwt         *domain.JWT
	logger      *zap.Logger
	mu          sync.RWMutex
	cache       *jwksCache
	rateLimiter *rate.Limiter
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

func NewJWTService(cfg *config.Config, logger *zap.Logger) JWTService {
	// Create JWT configuration
	jwtConfig := &domain.JWTConfig{
		AccessDuration:  cfg.JWTAccessDuration,
		RefreshDuration: cfg.JWTRefreshDuration,
	}

	// Validate JWT configuration
	if err := jwtConfig.Validate(); err != nil {
		logger.Fatal("Invalid JWT configuration", zap.Error(err))
	}

	jwt, err := domain.NewJWT(jwtConfig)
	if err != nil {
		logger.Fatal("Failed to initialize JWT service", zap.Error(err))
	}

	// Create rate limiter: 100 requests per second with burst of 200
	limiter := rate.NewLimiter(rate.Limit(100), 200)

	return &jwtService{
		jwt:         jwt,
		logger:      logger,
		cache:       newJWKSCache(),
		rateLimiter: limiter,
	}
}

// ValidateToken validates a JWT token and returns the claims
func (j *jwtService) ValidateToken(tokenString string) (*domain.Claims, error) {
	// Check rate limit
	if !j.rateLimiter.Allow() {
		return nil, domain.ErrRateLimitExceeded
	}

	j.mu.RLock()
	defer j.mu.RUnlock()

	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &domain.Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, domain.ErrInvalidSigningMethod
		}

		// Get public key
		publicKey := j.jwt.GetPublicKey()
		if publicKey == nil {
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
			return nil, fmt.Errorf("invalid token: %w", err)
		}
	}

	claims, ok := token.Claims.(*domain.Claims)
	if !ok {
		j.logger.Error("Invalid token (not valid)",
			zap.String("token_id", claims.ID))
		return nil, domain.ErrInvalidToken
	}

	// Check if token is blacklisted (by ID) ANTES da validação de claims/expiração
	if j.jwt.IsTokenBlacklisted(claims.ID) {
		return nil, domain.ErrTokenBlacklisted
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
		return nil, fmt.Errorf("%w: %s", domain.ErrInvalidClaims, err)
	}

	// Additional validation
	if claims.Subject == "" {
		j.logger.Error("Missing subject in token",
			zap.String("token_id", claims.ID))
		return nil, domain.ErrInvalidClaims
	}

	return claims, nil
}

func (j *jwtService) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	// Check rate limit
	if !j.rateLimiter.Allow() {
		return nil, domain.ErrRateLimitExceeded
	}

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
	publicKey := j.jwt.GetPublicKey()
	if publicKey == nil {
		j.logger.Error("Failed to get public key")
		return nil, fmt.Errorf("failed to get public key: %w", domain.ErrInvalidClient)
	}

	jwk, err := convertToJWK(publicKey, j.jwt.GetKeyID())
	if err != nil {
		j.logger.Error("Failed to convert public key to JWK",
			zap.Error(err))
		return nil, fmt.Errorf("failed to convert public key to JWK: %w", err)
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
	// Check rate limit
	if !j.rateLimiter.Allow() {
		return nil, domain.ErrRateLimitExceeded
	}

	j.mu.RLock()
	defer j.mu.RUnlock()

	// Generate access token
	accessTokenID := ulid.Make().String()
	accessClaims := domain.Claims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.jwt.GetAccessDuration())),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        accessTokenID,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = j.jwt.GetKeyID()
	accessTokenString, err := accessToken.SignedString(j.jwt.GetPrivateKey())
	if err != nil {
		j.logger.Error("Failed to sign access token",
			zap.Error(err),
			zap.String("token_id", accessTokenID),
			zap.String("user_id", userID.String()))
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate refresh token
	refreshTokenID := ulid.Make().String()
	refreshClaims := domain.Claims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.jwt.GetRefreshDuration())),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        refreshTokenID,
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshToken.Header["kid"] = j.jwt.GetKeyID()
	refreshTokenString, err := refreshToken.SignedString(j.jwt.GetPrivateKey())
	if err != nil {
		j.logger.Error("Failed to sign refresh token",
			zap.Error(err),
			zap.String("token_id", refreshTokenID),
			zap.String("user_id", userID.String()))
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	j.logger.Debug("Generated token pair",
		zap.String("access_token_id", accessTokenID),
		zap.String("refresh_token_id", refreshTokenID),
		zap.String("user_id", userID.String()),
		zap.String("key_id", j.jwt.GetKeyID()))

	return &domain.TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
	}, nil
}

func (j *jwtService) GetPublicKey() *rsa.PublicKey {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.jwt.GetPublicKey()
}

// RotateKeys rotates the JWT keys
func (j *jwtService) RotateKeys() error {
	// Check rate limit first
	if !j.rateLimiter.Allow() {
		return domain.ErrRateLimitExceeded
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	if err := j.jwt.RotateKey(); err != nil {
		j.logger.Error("Failed to rotate keys", zap.Error(err))
		return fmt.Errorf("failed to rotate keys: %w", err)
	}

	// Clear JWKS cache
	j.cache.mu.Lock()
	j.cache.keys = make(map[string]interface{})
	j.cache.lastSync = time.Time{}
	j.cache.mu.Unlock()

	j.logger.Info("JWT keys rotated successfully",
		zap.String("key_id", j.jwt.GetKeyID()),
		zap.Time("rotation_time", j.jwt.GetLastRotation()))

	return nil
}

// BlacklistToken adds a token to the blacklist
func (j *jwtService) BlacklistToken(tokenID string, expiresAt time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.jwt.BlacklistToken(tokenID, expiresAt)
	return nil
}

// IsTokenBlacklisted checks if a token is blacklisted
func (j *jwtService) IsTokenBlacklisted(tokenID string) bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.jwt.IsTokenBlacklisted(tokenID)
}

// convertToJWK converts an RSA public key to JWK format
func convertToJWK(publicKey *rsa.PublicKey, kid string) (map[string]interface{}, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	// Convert modulus and exponent to Base64URL without padding
	modulusBytes := publicKey.N.Bytes()
	nStr := base64.RawURLEncoding.EncodeToString(modulusBytes)
	eBytes := []byte{byte(publicKey.E)}
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
