package domain

import (
	"context"
	"crypto/rsa"

	"github.com/oklog/ulid/v2"
)

// JWTService defines the interface for JWT validation and JWKS retrieval
// This allows for easier mocking in tests
// Only the methods needed by the middleware are included
type JWTService interface {
	ValidateToken(token string) (*Claims, error)
	GetJWKS(context.Context) (map[string]interface{}, error)
	GetPublicKey() *rsa.PublicKey
	GenerateTokenPair(userID ulid.ULID, roles []string) (*TokenPair, error)
}
