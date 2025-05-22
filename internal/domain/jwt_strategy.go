package domain

import (
	"crypto/rsa"
	"time"
)

// JWTStrategy defines the interface for JWT signing strategies
type JWTStrategy interface {
	// Sign signs a JWT token with the strategy's private key
	Sign(claims *Claims) (string, error)
	// GetPublicKey returns the public key for token validation
	GetPublicKey() *rsa.PublicKey
	// GetKeyID returns the current key ID
	GetKeyID() string
	// RotateKey rotates the key pair
	RotateKey() error
	// GetLastRotation returns the last key rotation time
	GetLastRotation() time.Time
	// GetAccessDuration returns the access token duration
	GetAccessDuration() time.Duration
	// GetRefreshDuration returns the refresh token duration
	GetRefreshDuration() time.Duration
}

// VaultConfig holds the configuration for Vault integration
type VaultConfig struct {
	Address         string
	Token           string
	MountPath       string
	KeyName         string
	RoleName        string
	AuthMethod      string
	RetryCount      int
	RetryDelay      time.Duration
	Timeout         time.Duration
	AccessDuration  time.Duration
	RefreshDuration time.Duration
}

// LocalConfig holds the configuration for local key storage
type LocalConfig struct {
	KeyPath         string
	KeyPassword     string
	AccessDuration  time.Duration
	RefreshDuration time.Duration
}
