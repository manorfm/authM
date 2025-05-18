package application

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
)

var (
	ErrClientNotFound     = errors.New("client not found")
	ErrInvalidRedirectURI = errors.New("invalid redirect URI")
	ErrInvalidCode        = errors.New("invalid authorization code")
)

type authorizationCode struct {
	ClientID string
	UserID   string
	Scopes   []string
	Expires  time.Time
}

type OAuth2Service struct {
	clients map[string]*domain.OAuth2Client
	codes   map[string]*authorizationCode
	mu      sync.RWMutex
}

func NewOAuth2Service() *OAuth2Service {
	// Initialize with some test clients
	service := &OAuth2Service{
		clients: make(map[string]*domain.OAuth2Client),
		codes:   make(map[string]*authorizationCode),
	}

	// Add a test client
	service.clients["test"] = &domain.OAuth2Client{
		ID:           "test",
		Secret:       "test_secret",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	return service
}

func (s *OAuth2Service) ValidateClient(ctx context.Context, clientID, redirectURI string) (*domain.OAuth2Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.clients[clientID]
	if !exists {
		return nil, ErrClientNotFound
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
		return nil, ErrInvalidRedirectURI
	}

	return client, nil
}

func (s *OAuth2Service) GenerateAuthorizationCode(ctx context.Context, clientID, userID string, scopes []string) (string, error) {
	// Generate a random code
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)

	// Store the code
	s.mu.Lock()
	s.codes[code] = &authorizationCode{
		ClientID: clientID,
		UserID:   userID,
		Scopes:   scopes,
		Expires:  time.Now().Add(10 * time.Minute),
	}
	s.mu.Unlock()

	return code, nil
}

func (s *OAuth2Service) ValidateAuthorizationCode(ctx context.Context, code string) (*domain.OAuth2Client, string, []string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	authCode, exists := s.codes[code]
	if !exists {
		return nil, "", nil, ErrInvalidCode
	}

	if time.Now().After(authCode.Expires) {
		delete(s.codes, code)
		return nil, "", nil, ErrInvalidCode
	}

	client, exists := s.clients[authCode.ClientID]
	if !exists {
		return nil, "", nil, ErrClientNotFound
	}

	// Delete the code after use
	delete(s.codes, code)

	return client, authCode.UserID, authCode.Scopes, nil
}
