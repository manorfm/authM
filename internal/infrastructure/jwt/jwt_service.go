package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type JWTService struct {
	jwt    *domain.JWT
	logger *zap.Logger
}

func NewJWTService(cfg *config.Config, logger *zap.Logger) *JWTService {
	jwt, err := domain.NewJWT(
		cfg.JWTAccessDuration,
		cfg.JWTRefreshDuration,
	)
	if err != nil {
		logger.Fatal("Failed to initialize JWT service", zap.Error(err))
	}
	return &JWTService{
		jwt:    jwt,
		logger: logger,
	}
}

// ValidateToken validates a JWT token and returns the claims
func (j *JWTService) ValidateToken(tokenString string) (*domain.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return j.GetPublicKey(), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*domain.Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (j *JWTService) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	j.logger.Debug("Getting JWKS")

	// Get the public key from JWT service
	publicKey := j.jwt.GetPublicKey()
	if publicKey == nil {
		j.logger.Error("Failed to get public key")
		return nil, domain.ErrInvalidClient
	}

	// Convert public key to JWK format
	jwk, err := convertToJWK(publicKey)
	if err != nil {
		j.logger.Error("Failed to convert public key to JWK",
			zap.Error(err))
		return nil, err
	}

	return map[string]interface{}{
		"keys": []map[string]interface{}{jwk},
	}, nil
}

// GenerateTokenPair generates a new pair of access and refresh tokens
func (j *JWTService) GenerateTokenPair(userID ulid.ULID, roles []string) (*domain.TokenPair, error) {
	// Generate access token
	accessClaims := domain.Claims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.jwt.GetAccessDuration())),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        ulid.Make().String(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(j.jwt.GetPrivateKey())
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshClaims := domain.Claims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.jwt.GetRefreshDuration())),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        ulid.Make().String(),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(j.jwt.GetPrivateKey())
	if err != nil {
		return nil, err
	}

	return &domain.TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
	}, nil
}

func (j *JWTService) GetPublicKey() *rsa.PublicKey {
	return j.jwt.GetPublicKey()
}

func convertToJWK(publicKey *rsa.PublicKey) (map[string]interface{}, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	// Convert public key to JWK format
	nBytes, err := json.Marshal(publicKey.N.Bytes())
	if err != nil {
		return nil, err
	}

	eBytes, err := json.Marshal(publicKey.E)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": "1",
		"alg": "RS256",
		"n":   string(nBytes),
		"e":   string(eBytes),
	}, nil
}
