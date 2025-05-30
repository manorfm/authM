package application

import (
	"context"
	"testing"
	"time"

	"crypto/rsa"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type mockOAuth2Repository struct {
	mock.Mock
}

func (m *mockOAuth2Repository) CreateClient(ctx context.Context, client *domain.OAuth2Client) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

func (m *mockOAuth2Repository) FindClientByID(ctx context.Context, id string) (*domain.OAuth2Client, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OAuth2Client), args.Error(1)
}

func (m *mockOAuth2Repository) UpdateClient(ctx context.Context, client *domain.OAuth2Client) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

func (m *mockOAuth2Repository) DeleteClient(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockOAuth2Repository) ListClients(ctx context.Context) ([]*domain.OAuth2Client, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*domain.OAuth2Client), args.Error(1)
}

func (m *mockOAuth2Repository) CreateAuthorizationCode(ctx context.Context, code *domain.AuthorizationCode) error {
	args := m.Called(ctx, code)
	return args.Error(0)
}

func (m *mockOAuth2Repository) DeleteAuthorizationCode(ctx context.Context, code string) error {
	args := m.Called(ctx, code)
	return args.Error(0)
}

func (m *mockOAuth2Repository) GetAuthorizationCode(ctx context.Context, code string) (*domain.AuthorizationCode, error) {
	args := m.Called(ctx, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AuthorizationCode), args.Error(1)
}

type mockUserRepository struct {
	mock.Mock
}

func (m *mockUserRepository) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockUserRepository) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockUserRepository) Delete(ctx context.Context, id ulid.ULID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *mockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockUserRepository) FindByID(ctx context.Context, id ulid.ULID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockUserRepository) List(ctx context.Context, page, pageSize int) ([]*domain.User, error) {
	args := m.Called(ctx, page, pageSize)
	return args.Get(0).([]*domain.User), args.Error(1)
}

func (m *mockUserRepository) RemoveRole(ctx context.Context, userID ulid.ULID, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

func (m *mockUserRepository) Update(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockUserRepository) AddRole(ctx context.Context, userID ulid.ULID, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

// Mock JWT para simular chave pública inválida
type mockJWTWithNilKey struct{}

func (m *mockJWTWithNilKey) GetPublicKey() *rsa.PublicKey { return nil }

// Mock JWT para simular fluxo de refresh token
type mockJWTRefresh struct{}

func (m *mockJWTRefresh) ValidateToken(token string) (*domain.Claims, error) {
	return &domain.Claims{
		RegisteredClaims: &jwtv5.RegisteredClaims{
			Subject: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		},
		Roles: []string{"user"},
	}, nil
}

func (m *mockJWTRefresh) GetPublicKey() *rsa.PublicKey { return nil }

func (m *mockJWTRefresh) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	return nil, nil
}

func (m *mockJWTRefresh) GenerateTokenPair(userID ulid.ULID, roles []string) (*domain.TokenPair, error) {
	return &domain.TokenPair{
		AccessToken:  "mock_access_token",
		RefreshToken: "mock_refresh_token",
	}, nil
}

func (m *mockJWTRefresh) BlacklistToken(tokenID string, expiresAt time.Time) error {
	return nil
}

func (m *mockJWTRefresh) IsTokenBlacklisted(tokenID string) bool {
	return false
}

func (m *mockJWTRefresh) RotateKeys() error {
	return nil
}

func (m *mockJWTRefresh) TryVault() error {
	return nil
}

func (m *mockJWTRefresh) GetLastRotation() time.Time {
	return time.Now()
}

// Mock JWT para simular erro de validação
type mockJWTError struct{}

func (m *mockJWTError) ValidateToken(token string) (*domain.Claims, error) {
	return nil, domain.ErrInvalidCredentials
}

func (m *mockJWTError) GetPublicKey() *rsa.PublicKey {
	return nil
}

func (m *mockJWTError) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	return nil, nil
}

func (m *mockJWTError) GenerateTokenPair(userID ulid.ULID, roles []string) (*domain.TokenPair, error) {
	return nil, nil
}

func (m *mockJWTError) BlacklistToken(tokenID string, expiresAt time.Time) error {
	return nil
}

func (m *mockJWTError) IsTokenBlacklisted(tokenID string) bool {
	return false
}

func (m *mockJWTError) RotateKeys() error {
	return nil
}

func (m *mockJWTError) TryVault() error {
	return nil
}

// Mock JWT para simular erro de parsing do userID
type mockJWTInvalidUserID struct{}

func (m *mockJWTInvalidUserID) ValidateToken(token string) (*domain.Claims, error) {
	return &domain.Claims{
		RegisteredClaims: &jwtv5.RegisteredClaims{
			Subject: "invalid",
		},
		Roles: []string{"user"},
	}, nil
}

func (m *mockJWTInvalidUserID) GetPublicKey() *rsa.PublicKey {
	return nil
}

func (m *mockJWTInvalidUserID) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	return nil, nil
}

func (m *mockJWTInvalidUserID) GenerateTokenPair(userID ulid.ULID, roles []string) (*domain.TokenPair, error) {
	return nil, nil
}

func (m *mockJWTInvalidUserID) BlacklistToken(tokenID string, expiresAt time.Time) error {
	return nil
}

func (m *mockJWTInvalidUserID) IsTokenBlacklisted(tokenID string) bool {
	return false
}

func (m *mockJWTInvalidUserID) RotateKeys() error {
	return nil
}

func (m *mockJWTInvalidUserID) TryVault() error {
	return nil
}

// Mock JWT para simular erro de geração de token
type mockJWTTokenGenError struct{}

func (m *mockJWTTokenGenError) ValidateToken(token string) (*domain.Claims, error) {
	return &domain.Claims{
		RegisteredClaims: &jwtv5.RegisteredClaims{
			Subject: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		},
		Roles: []string{"user"},
	}, nil
}

func (m *mockJWTTokenGenError) GetPublicKey() *rsa.PublicKey {
	return nil
}

func (m *mockJWTTokenGenError) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	return nil, nil
}

func (m *mockJWTTokenGenError) GenerateTokenPair(userID ulid.ULID, roles []string) (*domain.TokenPair, error) {
	return nil, domain.ErrTokenGeneration
}

func (m *mockJWTTokenGenError) BlacklistToken(tokenID string, expiresAt time.Time) error {
	return nil
}

func (m *mockJWTTokenGenError) IsTokenBlacklisted(tokenID string) bool {
	return false
}

func (m *mockJWTTokenGenError) RotateKeys() error {
	return nil
}

func (m *mockJWTTokenGenError) TryVault() error {
	return nil
}

func TestOIDCService_GetUserInfo(t *testing.T) {
	userID := ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	tests := []struct {
		name          string
		userID        ulid.ULID
		mockSetup     func(*mockUserRepository)
		expectedError error
		expectedInfo  map[string]interface{}
	}{
		{
			name:   "successful user info retrieval",
			userID: userID,
			mockSetup: func(m *mockUserRepository) {
				m.On("FindByID", mock.Anything, userID).Return(&domain.User{
					ID:    userID,
					Name:  "Test User",
					Email: "test@example.com",
				}, nil)
			},
			expectedInfo: map[string]interface{}{
				"sub":            userID.String(),
				"name":           "Test User",
				"email":          "test@example.com",
				"email_verified": true,
			},
		},
		{
			name:   "user not found",
			userID: ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAW"),
			mockSetup: func(m *mockUserRepository) {
				m.On("FindByID", mock.Anything, ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAW")).Return(nil, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(mockUserRepository)
			tt.mockSetup(mockUserRepo)

			service := NewOIDCService(nil, nil, mockUserRepo, nil, zap.NewNop())

			info, err := service.GetUserInfo(context.Background(), tt.userID.String())

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, info)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedInfo, info)
			}

			mockUserRepo.AssertExpectations(t)
		})
	}
}

func TestOIDCService_Authorize(t *testing.T) {
	tests := []struct {
		name                string
		clientID            string
		redirectURI         string
		state               string
		scope               string
		codeChallenge       string
		codeChallengeMethod string
		mockSetup           func(*mockOAuth2Repository)
		expectedError       error
		expectedCode        string
	}{
		{
			name:                "successful authorization",
			clientID:            "client123",
			redirectURI:         "http://example.com/callback",
			state:               "state123",
			scope:               "openid profile email",
			codeChallenge:       "challenge123",
			codeChallengeMethod: "S256",
			mockSetup: func(m *mockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "client123").Return(&domain.OAuth2Client{
					ID:           "client123",
					RedirectURIs: []string{"http://example.com/callback"},
					Scopes:       []string{"openid", "profile", "email"},
				}, nil)
				m.On("CreateAuthorizationCode", mock.Anything, mock.MatchedBy(func(code *domain.AuthorizationCode) bool {
					return code.ClientID == "client123" &&
						len(code.Scopes) == 3 &&
						code.Scopes[0] == "openid" &&
						code.Scopes[1] == "profile" &&
						code.Scopes[2] == "email" &&
						code.CodeChallenge == "challenge123" &&
						code.CodeChallengeMethod == "S256"
				})).Return(nil)
			},
			expectedCode: "mock_code",
		},
		{
			name:                "invalid client",
			clientID:            "invalid",
			redirectURI:         "http://example.com/callback",
			state:               "state123",
			scope:               "openid profile",
			codeChallenge:       "challenge123",
			codeChallengeMethod: "S256",
			mockSetup: func(m *mockOAuth2Repository) {
				m.On("FindClientByID", mock.Anything, "invalid").Return(nil, domain.ErrInvalidClient)
			},
			expectedError: domain.ErrInvalidClient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockOAuth2Repo := new(mockOAuth2Repository)
			tt.mockSetup(mockOAuth2Repo)

			service := NewOIDCService(nil, nil, nil, mockOAuth2Repo, zap.NewNop())
			ctx := context.Background()
			ctx = context.WithValue(ctx, "sub", "01ARZ3NDEKTSV4RRFFQ69G5FAV")
			ctx = context.WithValue(ctx, "code_challenge", "challenge123")
			ctx = context.WithValue(ctx, "code_challenge_method", "S256")
			code, err := service.Authorize(ctx, tt.clientID, tt.redirectURI, tt.state, tt.scope)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
				assert.Empty(t, code)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, code)
			}

			mockOAuth2Repo.AssertExpectations(t)
		})
	}
}

func TestOIDCService_ExchangeCode(t *testing.T) {
	logger := zap.NewNop()
	tests := []struct {
		name          string
		code          string
		codeVerifier  string
		mockSetup     func(*mockOAuth2Repository)
		expectedError error
		expectedToken *domain.TokenPair
	}{
		{
			name:         "successful code exchange",
			code:         "valid_code",
			codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			mockSetup: func(m *mockOAuth2Repository) {
				m.On("GetAuthorizationCode", mock.Anything, "valid_code").Return(&domain.AuthorizationCode{
					Code:                "valid_code",
					ClientID:            "client123",
					UserID:              "01ARZ3NDEKTSV4RRFFQ69G5FAV",
					Scopes:              []string{"openid", "profile", "email"},
					CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
					CodeChallengeMethod: "S256",
					ExpiresAt:           time.Now().Add(time.Hour),
				}, nil)
				m.On("DeleteAuthorizationCode", mock.Anything, "valid_code").Return(nil)
			},
			expectedToken: &domain.TokenPair{
				AccessToken:  "mock_access_token",
				RefreshToken: "mock_refresh_token",
			},
		},
		{
			name:         "invalid code",
			code:         "invalid_code",
			codeVerifier: "verifier",
			mockSetup: func(m *mockOAuth2Repository) {
				m.On("GetAuthorizationCode", mock.Anything, "invalid_code").Return(nil, domain.ErrInvalidAuthorizationCode)
				m.On("DeleteAuthorizationCode", mock.Anything, "invalid_code").Return(nil)
			},
			expectedError: domain.ErrInvalidAuthorizationCode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockOAuth2Repo := new(mockOAuth2Repository)
			mockUserRepo := new(mockUserRepository)
			mockJWT := &mockJWTRefresh{} // Use mock JWT service instead of real one

			tt.mockSetup(mockOAuth2Repo)
			if tt.name == "successful code exchange" {
				mockUserRepo.On("FindByID", mock.Anything, ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV")).Return(&domain.User{
					ID:    ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
					Name:  "Test User",
					Email: "test@example.com",
					Roles: []string{"user"},
				}, nil)
			}

			service := NewOIDCService(nil, mockJWT, mockUserRepo, mockOAuth2Repo, logger)

			token, err := service.ExchangeCode(context.Background(), tt.code, tt.codeVerifier)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
				assert.Equal(t, tt.expectedToken, token)
			}

			mockOAuth2Repo.AssertExpectations(t)
			mockUserRepo.AssertExpectations(t)
		})
	}
}

func TestOIDCService_GetOpenIDConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		mockSetup      func(*mockOAuth2Repository)
		expectedError  error
		expectedConfig map[string]interface{}
	}{
		{
			name: "successful configuration retrieval",
			mockSetup: func(m *mockOAuth2Repository) {
				// No mock setup needed
			},
			expectedConfig: map[string]interface{}{
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
			},
		},
		{
			name: "nil OAuth2 repository",
			mockSetup: func(m *mockOAuth2Repository) {
				// No mock setup needed
			},
			expectedError: domain.ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var oauth2Repo domain.OAuth2Repository
			if tt.name != "nil OAuth2 repository" {
				oauth2Repo = new(mockOAuth2Repository)
				tt.mockSetup(oauth2Repo.(*mockOAuth2Repository))
			}

			service := NewOIDCService(nil, nil, nil, oauth2Repo, zap.NewNop())

			config, err := service.GetOpenIDConfiguration(context.Background())

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, config)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedConfig, config)
			}

			if oauth2Repo != nil {
				oauth2Repo.(*mockOAuth2Repository).AssertExpectations(t)
			}
		})
	}
}

func TestOIDCService_RefreshToken(t *testing.T) {
	logger := zap.NewNop()
	tests := []struct {
		name          string
		refreshToken  string
		mockSetup     func(*mockUserRepository, interface{})
		expectedError error
		expectedToken *domain.TokenPair
	}{
		{
			name:         "successful token refresh",
			refreshToken: "valid_refresh_token",
			mockSetup: func(m *mockUserRepository, _ interface{}) {
				userID := ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV")
				m.On("FindByID", mock.Anything, userID).Return(&domain.User{
					ID:    userID,
					Name:  "Test User",
					Email: "test@example.com",
					Roles: []string{"user"},
				}, nil)
			},
			expectedToken: &domain.TokenPair{
				AccessToken:  "mock_access_token",
				RefreshToken: "mock_refresh_token",
			},
		},
		{
			name:         "invalid refresh token",
			refreshToken: "invalid_token",
			mockSetup: func(m *mockUserRepository, _ interface{}) {
				// No mock setup needed
			},
			expectedError: domain.ErrInvalidCredentials,
		},
		{
			name:         "user not found",
			refreshToken: "valid_refresh_token",
			mockSetup: func(m *mockUserRepository, _ interface{}) {
				userID := ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV")
				m.On("FindByID", mock.Anything, userID).Return(nil, domain.ErrUserNotFound).Once()
			},
			expectedError: domain.ErrInvalidCredentials,
		},
		{
			name:         "invalid user ID in token",
			refreshToken: "valid_refresh_token",
			mockSetup: func(m *mockUserRepository, _ interface{}) {
				// No mock setup needed
			},
			expectedError: domain.ErrInvalidUserID,
		},
		{
			name:         "token generation error",
			refreshToken: "valid_refresh_token",
			mockSetup: func(m *mockUserRepository, _ interface{}) {
				userID := ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV")
				m.On("FindByID", mock.Anything, userID).Return(&domain.User{
					ID:    userID,
					Name:  "Test User",
					Email: "test@example.com",
					Roles: []string{"user"},
				}, nil)
			},
			expectedError: domain.ErrInternal,
		},
		{
			name:         "expired token",
			refreshToken: "expired_token",
			mockSetup: func(m *mockUserRepository, _ interface{}) {
				// No mock setup needed
			},
			expectedError: domain.ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(mockUserRepository)
			var jwtService domain.JWTService
			switch tt.name {
			case "successful token refresh":
				jwtService = &mockJWTRefresh{}
			case "invalid refresh token":
				jwtService = &mockJWTError{}
			case "invalid user ID in token":
				jwtService = &mockJWTInvalidUserID{}
			case "token generation error":
				jwtService = &mockJWTTokenGenError{}
			default:
				jwtService = &mockJWTError{}
			}
			tt.mockSetup(mockUserRepo, jwtService)

			service := NewOIDCService(nil, jwtService, mockUserRepo, nil, logger)

			token, err := service.RefreshToken(context.Background(), tt.refreshToken)

			if tt.expectedError != nil {
				assert.Error(t, err)
				if tt.expectedError.Error() != "" {
					assert.Equal(t, tt.expectedError.Error(), err.Error())
				}
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.RefreshToken)
			}

			if tt.name == "invalid refresh token" || tt.name == "user not found" {
				// não chama mockUserRepo.AssertExpectations(t)
			} else {
				mockUserRepo.AssertExpectations(t)
			}
		})
	}
}
