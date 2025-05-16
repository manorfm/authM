package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"
)

type Claims struct {
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

// TokenPair represents a pair of access and refresh tokens
type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

// JWT represents a JWT service
type JWT struct {
	privateKey      *rsa.PrivateKey
	publicKey       *rsa.PublicKey
	accessDuration  time.Duration
	refreshDuration time.Duration
}

// New creates a new JWT service
func New(accessDuration, refreshDuration time.Duration) (*JWT, error) {
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

// GenerateTokenPair generates a new pair of access and refresh tokens
func (j *JWT) GenerateTokenPair(userID ulid.ULID, roles []string) (*TokenPair, error) {
	// Generate access token
	accessClaims := Claims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.accessDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        ulid.Make().String(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(j.privateKey)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshClaims := Claims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.refreshDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        ulid.Make().String(),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(j.privateKey)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
	}, nil
}

// ValidateToken validates a JWT token and returns the claims
func (j *JWT) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
