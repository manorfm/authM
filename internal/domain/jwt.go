package domain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Constants for JWT configuration
const (
	// Default token durations
	DefaultAccessTokenDuration  = 15 * time.Minute
	DefaultRefreshTokenDuration = 24 * time.Hour

	// Minimum token durations
	MinAccessTokenDuration  = 1 * time.Millisecond
	MinRefreshTokenDuration = 1 * time.Second

	// Maximum token durations
	MaxAccessTokenDuration  = 1 * time.Hour
	MaxRefreshTokenDuration = 30 * 24 * time.Hour // 30 days

	// RSA key size
	RSAKeySize = 2048

	// JWKS cache duration
	JWKSCacheDuration = 5 * time.Minute
)

// Custom JWT error types
var (
	ErrInvalidToken         = errors.New("invalid token")
	ErrTokenExpired         = errors.New("token expired")
	ErrTokenGeneration      = errors.New("failed to generate token")
	ErrInvalidSigningMethod = errors.New("invalid signing method")
	ErrInvalidClaims        = errors.New("invalid claims")
	ErrSubjectMismatch      = errors.New("subject mismatch")
	ErrTokenRevoked         = errors.New("token has been revoked")
	ErrInvalidKeyConfig     = errors.New("invalid key configuration")
	ErrInvalidDuration      = errors.New("invalid token duration")
	ErrTokenBlacklisted     = errors.New("token is blacklisted")
	ErrRateLimitExceeded    = errors.New("rate limit exceeded")
)

// JWTConfig holds the configuration for JWT service
type JWTConfig struct {
	AccessDuration  time.Duration
	RefreshDuration time.Duration
}

// NewJWTConfig creates a new JWT configuration with default values
func NewJWTConfig() *JWTConfig {
	return &JWTConfig{
		AccessDuration:  DefaultAccessTokenDuration,
		RefreshDuration: DefaultRefreshTokenDuration,
	}
}

// Validate validates the JWT configuration
func (c *JWTConfig) Validate() error {
	if c.AccessDuration < MinAccessTokenDuration || c.AccessDuration > MaxAccessTokenDuration {
		return fmt.Errorf("%w: access duration must be between %v and %v",
			ErrInvalidDuration, MinAccessTokenDuration, MaxAccessTokenDuration)
	}
	if c.RefreshDuration < MinRefreshTokenDuration || c.RefreshDuration > MaxRefreshTokenDuration {
		return fmt.Errorf("%w: refresh duration must be between %v and %v",
			ErrInvalidDuration, MinRefreshTokenDuration, MaxRefreshTokenDuration)
	}
	if c.RefreshDuration <= c.AccessDuration {
		return fmt.Errorf("%w: refresh duration must be greater than access duration",
			ErrInvalidDuration)
	}
	return nil
}

// JWT defines the interface for JWT operations
type JWT struct {
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	config       *JWTConfig
	keyID        string
	lastRotation time.Time
	blacklist    map[string]time.Time // Token ID -> Expiration time
	mu           sync.RWMutex
}

// RefreshTokenRequest represents the request to refresh an access token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// TokenPair represents a pair of access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Claims struct {
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

// Valid implements the jwt.Claims interface
func (c *Claims) Valid() error {
	// Validate standard claims
	if c.ExpiresAt != nil && c.ExpiresAt.Before(time.Now()) {
		return ErrTokenExpired
	}

	if c.IssuedAt != nil && c.IssuedAt.After(time.Now()) {
		return errors.New("token issued in the future")
	}

	if c.NotBefore != nil && c.NotBefore.After(time.Now()) {
		return errors.New("token not yet valid")
	}

	if len(c.Roles) == 0 {
		return errors.New("no roles assigned")
	}

	if c.Subject == "" {
		return errors.New("subject is required")
	}

	return nil
}

// LoginResponse represents the response for a login request
type LoginResponse struct {
	User  *User      `json:"user"`
	Token *TokenPair `json:"token"`
}

// New creates a new JWT service
func NewJWT(config *JWTConfig) (*JWT, error) {
	if config == nil {
		config = NewJWTConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	jwt := &JWT{
		privateKey:   privateKey,
		publicKey:    &privateKey.PublicKey,
		config:       config,
		lastRotation: time.Now(),
		blacklist:    make(map[string]time.Time),
	}

	// Generate initial key ID
	if err := jwt.RotateKey(); err != nil {
		return nil, fmt.Errorf("failed to generate initial key ID: %w", err)
	}

	return jwt, nil
}

// GetPrivateKey returns the private key
func (j *JWT) GetPrivateKey() *rsa.PrivateKey {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.privateKey
}

// GetPublicKey returns the public key
func (j *JWT) GetPublicKey() *rsa.PublicKey {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.publicKey
}

// GetAccessDuration returns the access token duration
func (j *JWT) GetAccessDuration() time.Duration {
	return j.config.AccessDuration
}

// GetRefreshDuration returns the refresh token duration
func (j *JWT) GetRefreshDuration() time.Duration {
	return j.config.RefreshDuration
}

// GetKeyID returns the current key ID
func (j *JWT) GetKeyID() string {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.keyID
}

// GetLastRotation returns the last key rotation time
func (j *JWT) GetLastRotation() time.Time {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.lastRotation
}

// RotateKey generates a new key pair and updates the key ID
func (j *JWT) RotateKey() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	j.privateKey = privateKey
	j.publicKey = &privateKey.PublicKey
	j.keyID = generateKeyID(privateKey)
	j.lastRotation = time.Now()

	return nil
}

// BlacklistToken adds a token to the blacklist
func (j *JWT) BlacklistToken(tokenID string, expiresAt time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.blacklist[tokenID] = expiresAt
}

// IsTokenBlacklisted checks if a token is blacklisted
func (j *JWT) IsTokenBlacklisted(tokenID string) bool {
	j.mu.RLock()
	defer j.mu.RUnlock()

	if exp, ok := j.blacklist[tokenID]; ok {
		if time.Now().Before(exp) {
			return true
		}
		// Clean up expired blacklist entries
		delete(j.blacklist, tokenID)
	}
	return false
}

// CleanupBlacklist removes expired tokens from the blacklist
func (j *JWT) CleanupBlacklist() {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()
	for tokenID, exp := range j.blacklist {
		if now.After(exp) {
			delete(j.blacklist, tokenID)
		}
	}
}

// generateKeyID generates a unique key ID from the private key
func generateKeyID(key *rsa.PrivateKey) string {
	// Use the public key components to generate a unique ID
	modulus := key.N.Bytes()
	exponent := []byte{byte(key.E)}

	// Combine modulus and exponent
	data := append(modulus, exponent...)

	// Generate SHA-256 hash
	hash := sha256.Sum256(data)

	// Encode as base64url without padding
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
