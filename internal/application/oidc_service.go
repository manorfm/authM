package application

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type OIDCService struct {
	authService domain.AuthService
	jwtService  *jwt.JWT
	userRepo    domain.UserRepository
	oauthRepo   domain.OAuth2Repository
	logger      *zap.Logger
}

func NewOIDCService(
	authService domain.AuthService,
	jwtService *jwt.JWT,
	userRepo domain.UserRepository,
	oauthRepo domain.OAuth2Repository,
	logger *zap.Logger,
) domain.OIDCService {
	return &OIDCService{
		authService: authService,
		jwtService:  jwtService,
		userRepo:    userRepo,
		oauthRepo:   oauthRepo,
		logger:      logger,
	}
}

func (s *OIDCService) GetUserInfo(ctx context.Context, userID string) (map[string]interface{}, error) {
	s.logger.Debug("Getting user info",
		zap.String("user_id", userID))

	id, err := ulid.Parse(userID)
	if err != nil {
		s.logger.Error("Failed to parse user ID",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, err
	}

	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to find user",
			zap.String("user_id", userID),
			zap.Error(err))
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
	s.logger.Debug("Getting JWKS")

	// Get the public key from JWT service
	publicKey := s.jwtService.GetPublicKey()
	if publicKey == nil {
		s.logger.Error("Failed to get public key")
		return nil, domain.ErrInvalidClient
	}

	// Convert public key to JWK format
	jwk, err := s.convertToJWK(publicKey)
	if err != nil {
		s.logger.Error("Failed to convert public key to JWK",
			zap.Error(err))
		return nil, err
	}

	return map[string]interface{}{
		"keys": []map[string]interface{}{jwk},
	}, nil
}

func (s *OIDCService) GetOpenIDConfiguration(ctx context.Context) (map[string]interface{}, error) {
	s.logger.Debug("Getting OpenID configuration")

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
	s.logger.Debug("Exchanging authorization code for tokens",
		zap.String("code", code))

	// Get authorization code from repository
	authCode, err := s.oauthRepo.GetAuthorizationCode(ctx, code)
	if err != nil {
		s.logger.Error("Failed to get authorization code",
			zap.Error(err))
		return nil, fmt.Errorf("invalid authorization code: %w", err)
	}

	// Check if code is expired
	if authCode.ExpiresAt.Before(time.Now()) {
		s.logger.Error("Authorization code expired",
			zap.Time("expires_at", authCode.ExpiresAt))
		return nil, fmt.Errorf("authorization code expired")
	}

	// Get user from repository
	userID, err := ulid.Parse(authCode.UserID)
	if err != nil {
		s.logger.Error("Failed to parse user ID",
			zap.String("user_id", authCode.UserID),
			zap.Error(err))
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user",
			zap.String("user_id", authCode.UserID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate token pair
	infraTokenPair, err := s.jwtService.GenerateTokenPair(user.ID, user.Roles)
	if err != nil {
		s.logger.Error("Failed to generate token pair",
			zap.Error(err))
		return nil, fmt.Errorf("failed to generate token pair: %w", err)
	}

	// Delete used authorization code
	if err := s.oauthRepo.DeleteAuthorizationCode(ctx, code); err != nil {
		s.logger.Error("Failed to delete authorization code",
			zap.Error(err))
		// Don't return error here, as the tokens were already generated
	}

	// Convert infrastructure token pair to domain token pair
	tokenPair := &domain.TokenPair{
		AccessToken:  infraTokenPair.AccessToken,
		RefreshToken: infraTokenPair.RefreshToken,
	}

	return tokenPair, nil
}

func (s *OIDCService) RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenPair, error) {
	s.logger.Debug("Refreshing token")

	// Validate refresh token
	claims, err := s.jwtService.ValidateToken(refreshToken)
	if err != nil {
		s.logger.Error("Failed to validate refresh token",
			zap.Error(err))
		return nil, domain.ErrInvalidCredentials
	}

	// Parse user ID
	userID, err := ulid.Parse(claims.Subject)
	if err != nil {
		s.logger.Error("Failed to parse user ID",
			zap.String("user_id", claims.Subject),
			zap.Error(err))
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// Get user from repository
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user",
			zap.String("user_id", claims.Subject),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate new token pair
	infraTokenPair, err := s.jwtService.GenerateTokenPair(user.ID, user.Roles)
	if err != nil {
		s.logger.Error("Failed to generate token pair",
			zap.Error(err))
		return nil, fmt.Errorf("failed to generate token pair: %w", err)
	}

	// Convert infrastructure token pair to domain token pair
	tokenPair := &domain.TokenPair{
		AccessToken:  infraTokenPair.AccessToken,
		RefreshToken: infraTokenPair.RefreshToken,
	}

	return tokenPair, nil
}

func (s *OIDCService) Authorize(ctx context.Context, clientID, redirectURI, state, scope string) (string, error) {
	s.logger.Debug("Authorizing client",
		zap.String("client_id", clientID),
		zap.String("redirect_uri", redirectURI))

	// Validate client
	client, err := s.oauthRepo.FindClientByID(ctx, clientID)
	if err != nil {
		s.logger.Error("Failed to find client",
			zap.String("client_id", clientID),
			zap.Error(err))
		return "", domain.ErrInvalidClient
	}

	// Check if redirect URI is allowed
	validURI := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validURI = true
			break
		}
	}
	if !validURI {
		s.logger.Error("Invalid redirect URI",
			zap.String("redirect_uri", redirectURI))
		return "", domain.ErrInvalidClient
	}

	// Validate scope
	if scope != "" {
		validScope := false
		for _, allowedScope := range client.Scopes {
			if scope == allowedScope {
				validScope = true
				break
			}
		}
		if !validScope {
			s.logger.Error("Invalid scope",
				zap.String("scope", scope))
			return "", domain.ErrInvalidScope
		}
	}

	// Get user ID from context (set by auth middleware)
	userID, ok := ctx.Value("sub").(string)
	if !ok || userID == "" {
		s.logger.Error("Failed to get user ID from context")
		return "", domain.ErrInvalidCredentials
	}

	// Generate authorization code
	code := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	authCode := &domain.AuthorizationCode{
		Code:      code,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    []string{scope},
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
	}

	// Store authorization code
	if err := s.oauthRepo.CreateAuthorizationCode(ctx, authCode); err != nil {
		s.logger.Error("Failed to create authorization code",
			zap.Error(err))
		return "", fmt.Errorf("failed to create authorization code: %w", err)
	}

	return code, nil
}

func (s *OIDCService) convertToJWK(publicKey *rsa.PublicKey) (map[string]interface{}, error) {
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
