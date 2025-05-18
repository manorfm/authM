package domain

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken    = errors.New("invalid token")
	ErrTokenExpired    = errors.New("token expired")
	ErrTokenGeneration = errors.New("failed to generate token")
)

// JWT represents a JWT service
type JWT struct {
	privateKey      *rsa.PrivateKey
	publicKey       *rsa.PublicKey
	accessDuration  time.Duration
	refreshDuration time.Duration
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

// LoginResponse represents the response for a login request
type LoginResponse struct {
	User  *User      `json:"user"`
	Token *TokenPair `json:"token"`
}

// New creates a new JWT service
func NewJWT(accessDuration, refreshDuration time.Duration) (*JWT, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &JWT{
		privateKey:      privateKey,
		publicKey:       &privateKey.PublicKey,
		accessDuration:  accessDuration,
		refreshDuration: refreshDuration,
	}, nil
}

// GetPublicKey returns the public key for JWKS
func (j *JWT) GetPublicKey() *rsa.PublicKey {
	return j.publicKey
}

// GetPrivateKey returns the private key for signing tokens
func (j *JWT) GetPrivateKey() *rsa.PrivateKey {
	return j.privateKey
}

func (j *JWT) GetAccessDuration() time.Duration {
	return j.accessDuration
}

func (j *JWT) GetRefreshDuration() time.Duration {
	return j.refreshDuration
}
