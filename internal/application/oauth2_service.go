package application

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"go.uber.org/zap"
)

type OAuth2Service struct {
	oauthRepo domain.OAuth2Repository
	logger    *zap.Logger
}

func NewOAuth2Service(oauthRepo domain.OAuth2Repository, logger *zap.Logger) *OAuth2Service {
	return &OAuth2Service{
		oauthRepo: oauthRepo,
		logger:    logger,
	}
}

func (s *OAuth2Service) ValidateClient(ctx context.Context, clientID, redirectURI string) (*domain.OAuth2Client, error) {
	s.logger.Debug("Validating client",
		zap.String("client_id", clientID),
		zap.String("redirect_uri", redirectURI))

	client, err := s.oauthRepo.FindClientByID(ctx, clientID)
	if err != nil {
		s.logger.Error("Failed to find client",
			zap.String("client_id", clientID),
			zap.Error(err))
		return nil, domain.ErrClientNotFound
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
		return nil, domain.ErrInvalidRedirectURI
	}

	return client, nil
}

func (s *OAuth2Service) GenerateAuthorizationCode(ctx context.Context, clientID, userID string, scopes []string) (string, error) {
	s.logger.Debug("Generating authorization code",
		zap.String("client_id", clientID),
		zap.String("user_id", userID))

	// Generate a random code
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		s.logger.Error("Failed to generate random bytes for authorization code",
			zap.Error(err))
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)

	// Create authorization code in repository
	authCode := &domain.AuthorizationCode{
		Code:      code,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
	}

	if err := s.oauthRepo.CreateAuthorizationCode(ctx, authCode); err != nil {
		s.logger.Error("Failed to create authorization code",
			zap.Error(err))
		return "", err
	}

	return code, nil
}

func (s *OAuth2Service) ValidateAuthorizationCode(ctx context.Context, code string) (*domain.OAuth2Client, string, []string, error) {
	s.logger.Debug("Validating authorization code",
		zap.String("code", code))

	// Get authorization code from repository
	authCode, err := s.oauthRepo.GetAuthorizationCode(ctx, code)
	if err != nil {
		s.logger.Error("Failed to get authorization code",
			zap.Error(err))
		return nil, "", nil, domain.ErrInvalidAuthorizationCode
	}

	var deleteAuthorizationCode = func() {
		if err := s.oauthRepo.DeleteAuthorizationCode(ctx, code); err != nil {
			s.logger.Error("Failed to delete used authorization code",
				zap.Error(err))
		}
	}

	// Check if code is expired
	if time.Now().After(authCode.ExpiresAt) {
		s.logger.Error("Authorization code expired",
			zap.Time("expires_at", authCode.ExpiresAt))
		deleteAuthorizationCode()
		return nil, "", nil, domain.ErrInvalidAuthorizationCode
	}

	// Get client from repository
	client, err := s.oauthRepo.FindClientByID(ctx, authCode.ClientID)
	if err != nil {
		s.logger.Error("Failed to find client",
			zap.String("client_id", authCode.ClientID),
			zap.Error(err))
		return nil, "", nil, domain.ErrClientNotFound
	}

	deleteAuthorizationCode()

	return client, authCode.UserID, authCode.Scopes, nil
}
