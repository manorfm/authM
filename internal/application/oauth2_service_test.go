package application

import (
	"context"
	"testing"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockOAuth2Repository is a mock implementation of domain.OAuth2Repository
type MockOAuth2Repository struct {
	mock.Mock
}

func (m *MockOAuth2Repository) CreateClient(ctx context.Context, client *domain.OAuth2Client) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

func (m *MockOAuth2Repository) FindClientByID(ctx context.Context, id string) (*domain.OAuth2Client, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OAuth2Client), args.Error(1)
}

func (m *MockOAuth2Repository) UpdateClient(ctx context.Context, client *domain.OAuth2Client) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

func (m *MockOAuth2Repository) DeleteClient(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockOAuth2Repository) ListClients(ctx context.Context) ([]*domain.OAuth2Client, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*domain.OAuth2Client), args.Error(1)
}

func (m *MockOAuth2Repository) CreateAuthorizationCode(ctx context.Context, code *domain.AuthorizationCode) error {
	args := m.Called(ctx, code)
	return args.Error(0)
}

func (m *MockOAuth2Repository) GetAuthorizationCode(ctx context.Context, code string) (*domain.AuthorizationCode, error) {
	args := m.Called(ctx, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AuthorizationCode), args.Error(1)
}

func (m *MockOAuth2Repository) DeleteAuthorizationCode(ctx context.Context, code string) error {
	args := m.Called(ctx, code)
	return args.Error(0)
}

func TestOAuth2Service_ValidateClient(t *testing.T) {
	tests := []struct {
		name          string
		clientID      string
		redirectURI   string
		mockSetup     func(*MockOAuth2Repository)
		expectedError error
	}{
		{
			name:        "successful client validation",
			clientID:    "client123",
			redirectURI: "http://example.com/callback",
			mockSetup: func(m *MockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "client123").Return(&domain.OAuth2Client{
					ID:           "client123",
					Secret:       "secret",
					RedirectURIs: []string{"http://example.com/callback"},
					GrantTypes:   []string{"authorization_code"},
					Scopes:       []string{"openid"},
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}, nil)
			},
			expectedError: nil,
		},
		{
			name:        "client not found",
			clientID:    "nonexistent",
			redirectURI: "http://example.com/callback",
			mockSetup: func(m *MockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "nonexistent").Return(nil, domain.ErrClientNotFound)
			},
			expectedError: domain.ErrClientNotFound,
		},
		{
			name:        "invalid redirect URI",
			clientID:    "client123",
			redirectURI: "http://malicious.com/callback",
			mockSetup: func(m *MockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "client123").Return(&domain.OAuth2Client{
					ID:           "client123",
					Secret:       "secret",
					RedirectURIs: []string{"http://example.com/callback"},
					GrantTypes:   []string{"authorization_code"},
					Scopes:       []string{"openid"},
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}, nil)
			},
			expectedError: domain.ErrInvalidRedirectURI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockOAuth2Repository)
			tt.mockSetup(mockRepo)

			service := NewOAuth2Service(mockRepo, zap.NewNop())

			client, err := service.ValidateClient(context.Background(), tt.clientID, tt.redirectURI)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, tt.clientID, client.ID)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestOAuth2Service_GenerateAndValidateAuthorizationCode(t *testing.T) {
	tests := []struct {
		name                   string
		clientID               string
		userID                 string
		scopes                 []string
		mockSetup              func(*MockOAuth2Repository)
		expectedGeneratedError error
		expectedValidatedError error
	}{
		{
			name:     "successful code generation and validation",
			clientID: "client123",
			userID:   "user123",
			scopes:   []string{"openid", "profile"},
			mockSetup: func(m *MockOAuth2Repository) {
				// Setup for code generation
				m.On("CreateAuthorizationCode", mock.Anything, mock.MatchedBy(func(code *domain.AuthorizationCode) bool {
					return code.ClientID == "client123" &&
						code.UserID == "user123" &&
						len(code.Scopes) == 2 &&
						code.Scopes[0] == "openid" &&
						code.Scopes[1] == "profile"
				})).Return(nil)

				// Setup for code validation
				m.On("GetAuthorizationCode", mock.Anything, mock.Anything).Return(&domain.AuthorizationCode{
					Code:      "test_code",
					ClientID:  "client123",
					UserID:    "user123",
					Scopes:    []string{"openid", "profile"},
					ExpiresAt: time.Now().Add(time.Hour),
					CreatedAt: time.Now(),
				}, nil)

				m.On("FindClientByID", mock.Anything, "client123").Return(&domain.OAuth2Client{
					ID:           "client123",
					Secret:       "secret",
					RedirectURIs: []string{"http://example.com/callback"},
					GrantTypes:   []string{"authorization_code"},
					Scopes:       []string{"openid", "profile"},
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}, nil)

				m.On("DeleteAuthorizationCode", mock.Anything, mock.Anything).Return(nil)
			},
			expectedGeneratedError: nil,
			expectedValidatedError: nil,
		},
		{
			name:     "failed code generation",
			clientID: "client123",
			userID:   "user123",
			scopes:   []string{"openid"},
			mockSetup: func(m *MockOAuth2Repository) {
				m.On("CreateAuthorizationCode", mock.Anything, mock.Anything).Return(assert.AnError)
			},
			expectedGeneratedError: assert.AnError,
			expectedValidatedError: nil,
		},
		{
			name:     "expired code",
			clientID: "client123",
			userID:   "user123",
			scopes:   []string{"openid"},
			mockSetup: func(m *MockOAuth2Repository) {
				m.On("CreateAuthorizationCode", mock.Anything, mock.Anything).Return(nil)
				m.On("GetAuthorizationCode", mock.Anything, mock.Anything).Return(&domain.AuthorizationCode{
					Code:      "test_code",
					ClientID:  "client123",
					UserID:    "user123",
					Scopes:    []string{"openid"},
					ExpiresAt: time.Now().Add(-time.Hour), // Expired
					CreatedAt: time.Now().Add(-2 * time.Hour),
				}, nil)
				m.On("DeleteAuthorizationCode", mock.Anything, mock.Anything).Return(nil)
			},
			expectedGeneratedError: nil,
			expectedValidatedError: domain.ErrInvalidAuthorizationCode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockOAuth2Repository)
			tt.mockSetup(mockRepo)

			service := NewOAuth2Service(mockRepo, zap.NewNop())

			// Test code generation
			code, err := service.GenerateAuthorizationCode(context.Background(), tt.clientID, tt.userID, tt.scopes)
			if tt.expectedGeneratedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedGeneratedError, err)
				assert.Empty(t, code)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, code)

			// Test code validation
			client, userID, scopes, err := service.ValidateAuthorizationCode(context.Background(), code)
			if tt.expectedValidatedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedValidatedError, err)
				assert.Nil(t, client)
				assert.Empty(t, userID)
				assert.Nil(t, scopes)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, tt.clientID, client.ID)
				assert.Equal(t, tt.userID, userID)
				assert.Equal(t, tt.scopes, scopes)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}
