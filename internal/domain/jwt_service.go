package domain

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/oklog/ulid/v2"
)

// This allows for easier mocking in tests
// Only the methods needed by the middleware are included
// JWTService defines the interface for JWT operations
type JWTService interface {
	ValidateToken(token string) (*Claims, error)
	GetJWKS(ctx context.Context) (map[string]interface{}, error)
	GenerateTokenPair(userID ulid.ULID, roles []string) (*TokenPair, error)
	GetPublicKey() *rsa.PublicKey
	RotateKeys() error
	BlacklistToken(tokenID string, expiresAt time.Time) error
	IsTokenBlacklisted(tokenID string) bool
	TryVault() error
}
