package application

import (
	"context"
	"crypto/rsa"
	"encoding/json"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/ipede/user-manager-service/internal/infrastructure/repository"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type OIDCService struct {
	authService domain.AuthService
	jwtService  *jwt.JWT
	userRepo    *repository.UserRepository
	logger      *zap.Logger
}

func NewOIDCService(
	authService domain.AuthService,
	jwtService *jwt.JWT,
	userRepo *repository.UserRepository,
) domain.OIDCService {
	return &OIDCService{
		authService: authService,
		jwtService:  jwtService,
		userRepo:    userRepo,
	}
}

func (s *OIDCService) GetUserInfo(ctx context.Context, userID string) (map[string]interface{}, error) {
	id, err := ulid.Parse(userID)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"sub":            user.ID.String(),
		"name":           user.Name,
		"email":          user.Email,
		"email_verified": true,
	}, nil
}

func (s *OIDCService) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	// Get the public key from JWT service
	publicKey := s.jwtService.GetPublicKey()
	if publicKey == nil {
		return nil, domain.ErrInvalidClient
	}

	// Convert public key to JWK format
	jwk, err := s.convertToJWK(publicKey)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"keys": []map[string]interface{}{jwk},
	}, nil
}

func (s *OIDCService) GetOpenIDConfiguration(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"issuer":                                "http://localhost:8080",
		"authorization_endpoint":                "http://localhost:8080/oauth2/authorize",
		"token_endpoint":                        "http://localhost:8080/oauth2/token",
		"userinfo_endpoint":                     "http://localhost:8080/oauth2/userinfo",
		"jwks_uri":                              "http://localhost:8080/.well-known/jwks.json",
		"response_types_supported":              []string{"code", "token", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "name", "email"},
	}, nil
}

func (s *OIDCService) ExchangeCode(ctx context.Context, code string) (*domain.TokenPair, error) {
	// Validate the authorization code and get user info
	// This is a simplified implementation
	id, err := ulid.Parse("01HXSAXHRYPHM8ZP5STF47CFP8") // Example user ID
	if err != nil {
		return nil, err
	}

	scopes := []string{"openid", "profile"}

	// Generate token pair
	infraTokenPair, err := s.jwtService.GenerateTokenPair(id, scopes)
	if err != nil {
		return nil, err
	}

	tokenPair := &domain.TokenPair{
		AccessToken:  infraTokenPair.AccessToken,
		RefreshToken: infraTokenPair.RefreshToken,
	}

	return tokenPair, nil
}

func (s *OIDCService) RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenPair, error) {
	// Validate the refresh token and get user info
	// This is a simplified implementation
	id, err := ulid.Parse("01HXSAXHRYPHM8ZP5STF47CFP8") // Example user ID
	if err != nil {
		return nil, err
	}

	scopes := []string{"openid", "profile"}

	// Generate new token pair
	infraTokenPair, err := s.jwtService.GenerateTokenPair(id, scopes)
	if err != nil {
		return nil, err
	}

	tokenPair := &domain.TokenPair{
		AccessToken:  infraTokenPair.AccessToken,
		RefreshToken: infraTokenPair.RefreshToken,
	}

	return tokenPair, nil
}

func (s *OIDCService) Authorize(ctx context.Context, clientID, redirectURI, state, scope string) (string, error) {
	// Validate client and redirect URI
	// This is a simplified implementation
	if clientID != "client123" || redirectURI != "http://example.com/callback" {
		return "", domain.ErrInvalidClient
	}

	// Generate authorization code
	// In a real implementation, this would be stored and associated with the user
	code := "auth_code_123"

	return code, nil
}

// Helper function to convert RSA public key to JWK format
func (s *OIDCService) convertToJWK(key *rsa.PublicKey) (map[string]interface{}, error) {
	// Convert the public key to JWK format
	nBytes, err := json.Marshal(key.N.Bytes())
	if err != nil {
		return nil, err
	}

	eBytes, err := json.Marshal(key.E)
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
