package domain

import (
	"crypto/rsa"
	"time"
)

// JWTStrategy defines the interface for JWT operations
type JWTStrategy interface {
	// Sign signs a JWT token with the strategy's private key
	Sign(claims *Claims) (string, error)
	// Verify verifies a JWT token
	Verify(tokenString string) (*Claims, error)
	// GetPublicKey returns the public key for token validation
	GetPublicKey() *rsa.PublicKey
	// GetKeyID returns the current key ID
	GetKeyID() string
	// RotateKey rotates the key pair
	RotateKey() error
	// GetLastRotation returns the last key rotation time
	GetLastRotation() time.Time
}
