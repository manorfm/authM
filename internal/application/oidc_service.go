package application

import (
	"context"
	"strings"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type OIDCService struct {
	oauth2Service domain.OAuth2Service
	jwtService    domain.JWTService
	userRepo      domain.UserRepository
	config        *config.Config
	logger        *zap.Logger
}

func NewOIDCService(oauth2Service domain.OAuth2Service, jwtService domain.JWTService, userRepo domain.UserRepository, config *config.Config, logger *zap.Logger) *OIDCService {
	return &OIDCService{
		oauth2Service: oauth2Service,
		jwtService:    jwtService,
		userRepo:      userRepo,
		config:        config,
		logger:        logger,
	}
}

func (s *OIDCService) GetUserInfo(ctx context.Context, userID string) (map[string]interface{}, error) {
	s.logger.Debug("Getting user info",
		zap.String("user_id", userID))

	// Parse user ID
	id, err := ulid.Parse(userID)
	if err != nil {
		s.logger.Error("Invalid user ID",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, domain.ErrInvalidUserID
	}

	// Get user from repository
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to find user",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, domain.ErrUserNotFound
	}

	// Return user info
	return map[string]interface{}{
		"sub":            user.ID.String(),
		"name":           user.Name,
		"email":          user.Email,
		"email_verified": true,
	}, nil
}

func (s *OIDCService) GetOpenIDConfiguration(ctx context.Context) (map[string]interface{}, error) {
	s.logger.Debug("Getting OpenID configuration")

	if s.config == nil {
		s.logger.Error("Configuration is nil")
		return nil, domain.ErrInternal
	}

	return map[string]interface{}{
		"issuer":                                s.config.ServerURL,
		"authorization_endpoint":                s.config.ServerURL + "/oauth2/authorize",
		"token_endpoint":                        s.config.ServerURL + "/oauth2/token",
		"userinfo_endpoint":                     s.config.ServerURL + "/oauth2/userinfo",
		"jwks_uri":                              s.config.ServerURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code", "token", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "name", "email"},
	}, nil
}

func (s *OIDCService) ExchangeCode(ctx context.Context, code string, codeVerifier string) (*domain.TokenPair, error) {
	s.logger.Debug("Exchanging authorization code",
		zap.String("code", code))

	// Get authorization code from repository
	client, userID, scopes, err := s.oauth2Service.ValidateAuthorizationCode(ctx, code)
	if err != nil {
		return nil, err
	}

	// Parse user ID
	id, err := ulid.Parse(userID)
	if err != nil {
		s.logger.Error("Invalid user ID in authorization code",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, domain.ErrInvalidUserID
	}

	// Get user from repository
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to find user",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, domain.ErrUserNotFound
	}

	// Generate token pair with scopes
	tokenPair, err := s.jwtService.GenerateTokenPair(user.ID, user.Roles)
	if err != nil {
		s.logger.Error("Failed to generate token pair",
			zap.Error(err))
		return nil, domain.ErrFailedGenerateToken
	}

	// Log successful exchange
	s.logger.Info("Successfully exchanged authorization code",
		zap.String("client_id", client.ID),
		zap.String("user_id", userID),
		zap.Strings("scopes", scopes))

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
	userID, err := ulid.Parse(claims.RegisteredClaims.Subject)
	if err != nil {
		s.logger.Error("Invalid user ID in refresh token",
			zap.String("user_id", claims.RegisteredClaims.Subject),
			zap.Error(err))
		return nil, domain.ErrInvalidUserID
	}

	// Get user from repository
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to find user",
			zap.String("user_id", claims.RegisteredClaims.Subject),
			zap.Error(err))
		return nil, domain.ErrInvalidCredentials
	}

	// Generate new token pair
	tokenPair, err := s.jwtService.GenerateTokenPair(user.ID, user.Roles)
	if err != nil {
		s.logger.Error("Failed to generate token pair",
			zap.Error(err))
		return nil, domain.ErrInternal
	}

	return tokenPair, nil
}

func (s *OIDCService) Authorize(ctx context.Context, clientID, redirectURI, state, scope string) (string, error) {
	s.logger.Debug("Authorizing request",
		zap.String("client_id", clientID),
		zap.String("redirect_uri", redirectURI),
		zap.String("state", state),
		zap.String("scope", scope))

	// Get user ID from context
	userID, ok := domain.GetSubject(ctx)
	if !ok {
		s.logger.Error("User ID not found in context")
		return "", domain.ErrUnauthorized
	}

	// Validate client
	client, err := s.oauth2Service.ValidateClient(ctx, clientID, redirectURI)
	if err != nil {
		return "", err
	}

	// Get code challenge from context
	codeChallenge, _ := domain.GetCodeChallenge(ctx)
	codeChallengeMethod, _ := domain.GetCodeChallengeMethod(ctx)

	// Parse and validate scopes
	requestedScopes := strings.Split(scope, " ")
	if len(requestedScopes) == 0 {
		s.logger.Error("No scopes provided")
		return "", domain.ErrInvalidScope
	}

	// Validate that all requested scopes are allowed for this client
	validScopes := make([]string, 0)
	for _, requestedScope := range requestedScopes {
		valid := false
		for _, allowedScope := range client.Scopes {
			if requestedScope == allowedScope {
				valid = true
				validScopes = append(validScopes, requestedScope)
				break
			}
		}
		if !valid {
			s.logger.Error("Invalid scope requested",
				zap.String("scope", requestedScope),
				zap.Strings("allowed_scopes", client.Scopes))
			return "", domain.ErrInvalidScope
		}
	}

	// Generate authorization code
	code, err := s.oauth2Service.GenerateAuthorizationCode(ctx, client.ID, userID, validScopes, codeChallenge, codeChallengeMethod)
	if err != nil {
		return "", err
	}

	return code, nil
}
